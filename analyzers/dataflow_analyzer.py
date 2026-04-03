"""
IDA-Graphy Data Flow Analyzer
==============================

核心功能：使用Hex-Rays ctree visitor分析函数内的读写操作，生成READS和WRITES边。

关键识别：
- WRITES边：捕获 cot_asg, cot_asgbor, cot_asgband, cot_asgadd 等赋值操作
- READS边：捕获 cot_memref, cot_memptr, cot_obj 等访存操作
- 结构体成员：使用 ida_bytes.is_stroff() 和 get_stroff_path()
- 全局变量：检查地址是否在.data/.bss段
"""

import ida_hexrays
import ida_bytes
import ida_segment
import ida_typeinf
import ida_struct
import ida_nalt
import idautils
import idc
from typing import List, Dict, Tuple, Optional, Any
import hashlib


class DataSlot:
    """数据槽位表示（结构体成员或全局变量）"""
    
    def __init__(self, uid: str, base_type: str, offset: int, size: int, 
                 name: str, is_global: bool):
        self.uid = uid
        self.base_type = base_type
        self.offset = offset
        self.size = size
        self.name = name
        self.is_global = is_global
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'uid': self.uid,
            'base_type': self.base_type,
            'offset': self.offset,
            'size': self.size,
            'name': self.name,
            'is_global': self.is_global
        }


class DataFlowVisitor(ida_hexrays.ctree_visitor_t):
    """
    基于Hex-Rays ctree的数据流分析器
    
    遍历反编译后的C语法树，识别：
    1. WRITES：赋值操作 (=, |=, &=, +=)
    2. READS：内存读取操作（特别标记条件判断中的读取）
    """
    
    def __init__(self, func_ea: int, func_uid: str, binary_hash: str):
        """
        初始化visitor
        
        Args:
            func_ea: 函数起始地址
            func_uid: 函数唯一ID（用于边的起点）
            binary_hash: 二进制文件hash（用于生成全局变量DataSlot ID）
        """
        super().__init__(ida_hexrays.CV_FAST)
        self.func_ea = func_ea
        self.func_uid = func_uid
        self.binary_hash = binary_hash
        
        # 存储识别到的数据流边
        self.writes = []  # List[Dict]: WRITES边信息
        self.reads = []   # List[Dict]: READS边信息
        
        # 条件语句深度计数（用于判断读取是否在条件中）
        self.condition_depth = 0
        
        # 已识别的DataSlot缓存（避免重复创建）
        self.dataslot_cache = {}  # {uid: DataSlot}
    
    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        """
        访问表达式节点
        
        识别：
        - 赋值操作 (cot_asg, cot_asgbor, cot_asgband, cot_asgadd)
        - 内存访问 (cot_memref, cot_memptr, cot_obj)
        
        Returns:
            0: 继续遍历
        """
        # ===== 识别WRITES边 =====
        
        # 1. 简单赋值: a = b
        if expr.op == ida_hexrays.cot_asg:
            self._handle_assignment(expr, 'ASSIGN')
        
        # 2. 按位或赋值: a |= b (常用于置位标志)
        elif expr.op == ida_hexrays.cot_asgbor:
            self._handle_assignment(expr, 'OR')
        
        # 3. 按位与赋值: a &= b (常用于清除标志)
        elif expr.op == ida_hexrays.cot_asgband:
            self._handle_assignment(expr, 'AND')
        
        # 4. 加法赋值: a += b
        elif expr.op == ida_hexrays.cot_asgadd:
            self._handle_assignment(expr, 'ADD')
        
        # 5. 减法赋值: a -= b
        elif expr.op == ida_hexrays.cot_asgsub:
            self._handle_assignment(expr, 'SUB')
        
        # 6. 乘法赋值: a *= b
        elif expr.op == ida_hexrays.cot_asgmul:
            self._handle_assignment(expr, 'MUL')
        
        # ===== 识别READS边 =====
        
        # 读取操作：内存访问、对象访问
        if self._is_memory_access(expr):
            self._handle_memory_read(expr)
        
        return 0  # 继续遍历子节点
    
    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        """
        访问语句节点
        
        追踪条件语句（if/switch/while/for），用于标记条件读取
        
        Returns:
            0: 继续遍历
        """
        # 进入条件语句
        if insn.op == ida_hexrays.cit_if:
            # if语句的条件表达式
            self.condition_depth += 1
            if insn.cif and insn.cif.expr:
                insn.cif.expr.accept(self)
            self.condition_depth -= 1
            
            # 遍历then和else分支（非条件上下文）
            if insn.cif.ithen:
                insn.cif.ithen.accept(self)
            if insn.cif.ielse:
                insn.cif.ielse.accept(self)
            
            return 1  # 阻止自动遍历（已手动遍历）
        
        elif insn.op == ida_hexrays.cit_switch:
            # switch语句的条件表达式
            self.condition_depth += 1
            if insn.cswitch and insn.cswitch.expr:
                insn.cswitch.expr.accept(self)
            self.condition_depth -= 1
            
            # 遍历case分支
            if insn.cswitch.cases:
                for case in insn.cswitch.cases:
                    case.accept(self)
            
            return 1
        
        elif insn.op in [ida_hexrays.cit_while, ida_hexrays.cit_do]:
            # while/do-while循环的条件
            self.condition_depth += 1
            if hasattr(insn, 'cloop') and insn.cloop and insn.cloop.expr:
                insn.cloop.expr.accept(self)
            self.condition_depth -= 1
            
            # 遍历循环体
            if hasattr(insn, 'cloop') and insn.cloop and insn.cloop.body:
                insn.cloop.body.accept(self)
            
            return 1
        
        elif insn.op == ida_hexrays.cit_for:
            # for循环的条件（init/cond/step中的cond）
            if hasattr(insn, 'cfor') and insn.cfor:
                # init和step是普通语句
                if insn.cfor.init:
                    insn.cfor.init.accept(self)
                
                # 条件表达式
                self.condition_depth += 1
                if insn.cfor.expr:
                    insn.cfor.expr.accept(self)
                self.condition_depth -= 1
                
                if insn.cfor.step:
                    insn.cfor.step.accept(self)
                
                # 循环体
                if insn.cfor.body:
                    insn.cfor.body.accept(self)
            
            return 1
        
        return 0  # 继续遍历
    
    def _handle_assignment(self, expr: ida_hexrays.cexpr_t, op_type: str):
        """
        处理赋值操作，生成WRITES边
        
        Args:
            expr: 赋值表达式（如 a = b）
            op_type: 操作类型 ('ASSIGN', 'OR', 'AND', 'ADD')
        """
        # 分析左值（被写入的目标）
        lhs = expr.x  # 左值
        rhs = expr.y  # 右值
        
        slot = self._analyze_lvalue(lhs)
        if slot:
            # 提取右值常量（如果是常量）
            const_val = self._extract_const(rhs)
            
            # 创建WRITES边
            write_edge = {
                'from': self.func_uid,
                'to': slot.uid,
                'op_type': op_type,
                'const_val': const_val,
                'loc': expr.ea  # 操作发生的地址
            }
            self.writes.append(write_edge)
            
            # 缓存DataSlot
            if slot.uid not in self.dataslot_cache:
                self.dataslot_cache[slot.uid] = slot
    
    def _handle_memory_read(self, expr: ida_hexrays.cexpr_t):
        """
        处理内存读取操作，生成READS边
        
        Args:
            expr: 内存访问表达式
        """
        slot = self._analyze_slot(expr)
        if slot:
            # 判断是否在条件语句中
            is_conditional = self.condition_depth > 0
            
            # 提取操作类型
            op_type = self._get_operation_type(expr)
            
            # 创建READS边
            read_edge = {
                'from': self.func_uid,
                'to': slot.uid,
                'condition': is_conditional,  # 关键：标记是否为控制流依赖
                'op_type': op_type,
                'const_val': None  # 读取操作通常不记录常量值
            }
            self.reads.append(read_edge)
            
            # 缓存DataSlot
            if slot.uid not in self.dataslot_cache:
                self.dataslot_cache[slot.uid] = slot
    
    def _analyze_lvalue(self, expr: ida_hexrays.cexpr_t) -> Optional[DataSlot]:
        """
        分析左值表达式，识别DataSlot
        
        支持的模式：
        1. 结构体成员访问: obj.member, ptr->member
        2. 全局变量访问: g_Config
        3. 数组访问: arr[idx] (如果arr是全局或结构体成员)
        
        Args:
            expr: 左值表达式
            
        Returns:
            DataSlot对象，如果无法识别则返回None
        """
        return self._analyze_slot(expr)
    
    def _analyze_slot(self, expr: ida_hexrays.cexpr_t) -> Optional[DataSlot]:
        """
        通用的DataSlot识别函数
        
        Args:
            expr: 表达式节点
            
        Returns:
            DataSlot对象或None
        """
        # 1. 结构体成员访问: obj.member
        if expr.op == ida_hexrays.cot_memref:
            return self._analyze_struct_member(expr)
        
        # 2. 指针成员访问: ptr->member (通常表示为 *ptr.member)
        elif expr.op == ida_hexrays.cot_memptr:
            return self._analyze_struct_member(expr)
        
        # 3. 全局变量或局部变量对象
        elif expr.op == ida_hexrays.cot_obj:
            # 检查是否为全局变量
            if is_global_var(expr.obj_ea):
                return self._create_global_slot(expr.obj_ea)
        
        # 4. 指针解引用: *ptr
        elif expr.op == ida_hexrays.cot_ptr:
            # 尝试追溯指针来源
            base_expr = expr.x
            if base_expr and base_expr.op == ida_hexrays.cot_add:
                # 可能是 *(base + offset) 形式的结构体访问
                return self._analyze_slot(base_expr)
        
        # 5. 数组访问: arr[idx]
        elif expr.op == ida_hexrays.cot_idx:
            # 检查数组基址是否为全局或结构体成员
            array_base = expr.x
            return self._analyze_slot(array_base)
        
        return None
    
    def _analyze_struct_member(self, expr: ida_hexrays.cexpr_t) -> Optional[DataSlot]:
        """
        分析结构体成员访问
        
        Args:
            expr: cot_memref 或 cot_memptr 表达式
            
        Returns:
            DataSlot对象
        """
        try:
            # 获取结构体基址表达式
            struct_expr = expr.x
            
            # 获取成员偏移量
            member_offset = expr.m
            
            # 获取结构体类型
            struct_type = struct_expr.type
            if not struct_type:
                return None
            
            # 去除指针类型（如果是 ptr->member）
            if struct_type.is_ptr():
                struct_type = struct_type.get_pointed_object()
            
            if not struct_type.is_struct():
                return None
            
            # 获取结构体名称
            struct_name = struct_type.dstr()
            
            # 清理结构体名称（去除前缀）
            struct_name = self._clean_struct_name(struct_name)
            
            # 获取成员名称
            member_name = self._get_member_name(struct_type, member_offset)
            
            # 获取成员大小
            member_size = self._get_member_size(struct_type, member_offset)
            
            # 生成DataSlot ID（跨二进制共享）
            slot_uid = self._generate_struct_slot_id(struct_name, member_offset)
            
            return DataSlot(
                uid=slot_uid,
                base_type=struct_name,
                offset=member_offset,
                size=member_size,
                name=member_name,
                is_global=False
            )
        
        except Exception as e:
            # 结构体信息不完整，忽略
            return None
    
    def _create_global_slot(self, ea: int) -> Optional[DataSlot]:
        """
        创建全局变量DataSlot
        
        Args:
            ea: 全局变量地址
            
        Returns:
            DataSlot对象
        """
        try:
            # 获取全局变量名称
            var_name = idc.get_name(ea)
            if not var_name:
                var_name = f"global_{hex(ea)}"
            
            # 获取大小
            var_size = idc.get_item_size(ea)
            if var_size == 0:
                var_size = 4  # 默认4字节
            
            # 计算RVA
            base_addr = ida_nalt.get_imagebase()
            rva = ea - base_addr
            
            # 生成DataSlot ID（二进制私有）
            slot_uid = self._generate_global_slot_id(rva)
            
            return DataSlot(
                uid=slot_uid,
                base_type='GLOBAL',
                offset=rva,
                size=var_size,
                name=var_name,
                is_global=True
            )
        
        except Exception as e:
            return None
    
    def _extract_const(self, expr: ida_hexrays.cexpr_t) -> Optional[str]:
        """
        从表达式中提取常量值
        
        Args:
            expr: 表达式节点
            
        Returns:
            常量值的字符串表示（十六进制），如 '0x80'
        """
        return extract_const_value(expr)
    
    def _is_memory_access(self, expr: ida_hexrays.cexpr_t) -> bool:
        """
        判断表达式是否为内存访问操作
        
        Args:
            expr: 表达式节点
            
        Returns:
            True if 是内存访问
        """
        return expr.op in [
            ida_hexrays.cot_memref,  # obj.member
            ida_hexrays.cot_memptr,  # ptr->member
            ida_hexrays.cot_obj,     # 对象访问（全局/局部变量）
            ida_hexrays.cot_idx,     # 数组访问 arr[idx]
        ]
    
    def _get_operation_type(self, expr: ida_hexrays.cexpr_t) -> str:
        """
        获取操作类型字符串
        
        Args:
            expr: 表达式节点
            
        Returns:
            操作类型 ('MEMREF', 'MEMPTR', 'OBJ', 'IDX')
        """
        op_map = {
            ida_hexrays.cot_memref: 'MEMREF',
            ida_hexrays.cot_memptr: 'MEMPTR',
            ida_hexrays.cot_obj: 'OBJ',
            ida_hexrays.cot_idx: 'IDX',
            ida_hexrays.cot_ptr: 'PTR',
        }
        return op_map.get(expr.op, 'UNKNOWN')
    
    def _clean_struct_name(self, name: str) -> str:
        """清理结构体名称（去除 'struct ' 前缀等）"""
        name = name.strip()
        if name.startswith('struct '):
            name = name[7:]
        if name.startswith('_'):
            name = name[1:]
        return name
    
    def _get_member_name(self, struct_type: ida_typeinf.tinfo_t, 
                         offset: int) -> str:
        """
        获取结构体成员名称
        
        Args:
            struct_type: 结构体类型
            offset: 成员偏移量（字节）
            
        Returns:
            成员名称
        """
        try:
            # 转换偏移量：字节 -> 位
            offset_bits = offset * 8
            
            # 遍历结构体成员
            udt_data = ida_typeinf.udt_type_data_t()
            if struct_type.get_udt_details(udt_data):
                for i in range(udt_data.size()):
                    member = udt_data[i]
                    if member.offset <= offset_bits < (member.offset + member.size * 8):
                        return member.name
            
            return f"field_{hex(offset)}"
        
        except:
            return f"field_{hex(offset)}"
    
    def _get_member_size(self, struct_type: ida_typeinf.tinfo_t, 
                         offset: int) -> int:
        """
        获取结构体成员大小
        
        Args:
            struct_type: 结构体类型
            offset: 成员偏移量（字节）
            
        Returns:
            成员大小（字节）
        """
        try:
            offset_bits = offset * 8
            udt_data = ida_typeinf.udt_type_data_t()
            if struct_type.get_udt_details(udt_data):
                for i in range(udt_data.size()):
                    member = udt_data[i]
                    if member.offset <= offset_bits < (member.offset + member.size * 8):
                        return member.size
            
            return 4  # 默认4字节
        
        except:
            return 4
    
    def _generate_struct_slot_id(self, struct_name: str, offset: int) -> str:
        """
        生成结构体DataSlot ID（跨二进制共享）
        
        格式: MD5(StructName_Offset)
        
        Args:
            struct_name: 结构体名称
            offset: 偏移量（字节）
            
        Returns:
            32位MD5哈希字符串
        """
        input_str = f"{struct_name}_{int(offset)}"
        return hashlib.md5(input_str.encode('utf-8')).hexdigest()
    
    def _generate_global_slot_id(self, rva: int) -> str:
        """
        生成全局变量DataSlot ID（二进制私有）
        
        格式: MD5(BinaryHash_GLOBAL_RVA)
        
        Args:
            rva: 相对虚拟地址
            
        Returns:
            32位MD5哈希字符串
        """
        rva_str = hex(rva)[2:].lower()
        input_str = f"{self.binary_hash}_GLOBAL_{rva_str}"
        return hashlib.md5(input_str.encode('utf-8')).hexdigest()
    
    def get_dataslots(self) -> List[DataSlot]:
        """获取所有识别到的DataSlot对象"""
        return list(self.dataslot_cache.values())


# ====== 辅助函数 ======

def extract_const_value(expr: ida_hexrays.cexpr_t) -> Optional[str]:
    """
    从表达式中提取常量值
    
    支持的类型：
    - 数值常量 (cot_num)
    - 字符串常量 (cot_str)
    
    Args:
        expr: 表达式节点
        
    Returns:
        常量值的字符串表示，例如：
        - 数值: '0x80', '1', '0'
        - 字符串: '"Hello"'
        - 未识别: None
    """
    if expr.op == ida_hexrays.cot_num:
        # 数值常量
        val = expr.numval()
        # 根据值的大小选择十六进制或十进制
        if val > 9:
            return hex(val)
        else:
            return str(val)
    
    elif expr.op == ida_hexrays.cot_str:
        # 字符串常量
        return f'"{expr.string}"'
    
    elif expr.op == ida_hexrays.cot_helper:
        # 辅助表达式，可能包含常量
        # 尝试递归提取
        if hasattr(expr, 'x') and expr.x:
            return extract_const_value(expr.x)
    
    return None


def is_global_var(ea: int) -> bool:
    """
    判断地址是否为全局变量
    
    检查方法：
    1. 地址是否在.data或.bss段
    2. 是否有有效的段信息
    
    Args:
        ea: 地址
        
    Returns:
        True if 是全局变量
    """
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    
    # 检查段类型
    seg_type = seg.type
    if seg_type in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]:
        return True
    
    # 检查段名称（备用方法）
    seg_name = ida_segment.get_segm_name(seg).lower()
    if any(name in seg_name for name in ['.data', '.bss', '.rdata', 'data', 'bss']):
        return True
    
    return False


def extract_all_dataslots(binary_hash: str) -> List[DataSlot]:
    """
    从IDA数据库中提取所有DataSlot节点
    
    包括：
    1. 遍历所有结构体定义，扁平化所有成员
    2. 遍历所有全局变量
    
    Args:
        binary_hash: 二进制文件hash（用于生成全局变量ID）
        
    Returns:
        DataSlot对象列表
    """
    dataslots = []
    
    # ===== 1. 提取所有结构体成员 =====
    struct_count = ida_struct.get_struc_qty()
    for idx in range(struct_count):
        sid = ida_struct.get_struc_by_idx(idx)
        struc = ida_struct.get_struc(sid)
        if not struc:
            continue
        
        struct_name = ida_struct.get_struc_name(sid)
        
        # 跳过匿名结构体
        if not struct_name or struct_name.startswith('$'):
            continue
        
        # 扁平化结构体成员
        slots = flatten_struct(struct_name, binary_hash)
        dataslots.extend(slots)
    
    # ===== 2. 提取所有全局变量 =====
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg:
            continue
        
        # 只处理.data和.bss段
        if seg.type not in [ida_segment.SEG_DATA, ida_segment.SEG_BSS]:
            continue
        
        # 遍历段中的所有名称
        ea = seg.start_ea
        while ea < seg.end_ea:
            # 检查该地址是否有名称
            name = idc.get_name(ea)
            if name and not name.startswith('off_') and not name.startswith('unk_'):
                # 创建全局变量DataSlot
                var_size = idc.get_item_size(ea)
                if var_size == 0:
                    var_size = 4
                
                base_addr = ida_nalt.get_imagebase()
                rva = ea - base_addr
                
                # 生成ID
                rva_str = hex(rva)[2:].lower()
                input_str = f"{binary_hash}_GLOBAL_{rva_str}"
                slot_uid = hashlib.md5(input_str.encode('utf-8')).hexdigest()
                
                slot = DataSlot(
                    uid=slot_uid,
                    base_type='GLOBAL',
                    offset=rva,
                    size=var_size,
                    name=name,
                    is_global=True
                )
                dataslots.append(slot)
            
            # 移动到下一个项目
            next_ea = idc.next_head(ea)
            if next_ea <= ea:
                break
            ea = next_ea
    
    return dataslots


def flatten_struct(struct_name: str, binary_hash: str, 
                   base_offset: int = 0, prefix: str = '') -> List[DataSlot]:
    """
    递归扁平化结构体，生成所有成员的DataSlot
    
    处理嵌套结构体，计算绝对偏移量
    
    Args:
        struct_name: 结构体名称
        binary_hash: 二进制hash（仅用于全局变量，结构体成员不需要）
        base_offset: 基础偏移量（用于嵌套）
        prefix: 成员名前缀（用于嵌套）
        
    Returns:
        DataSlot对象列表
    """
    slots = []
    
    try:
        # 获取结构体ID
        sid = ida_struct.get_struc_id(struct_name)
        if sid == ida_idaapi.BADADDR:
            return slots
        
        struc = ida_struct.get_struc(sid)
        if not struc:
            return slots
        
        # 遍历所有成员
        for i in range(struc.memqty):
            member = struc.get_member(i)
            if not member:
                continue
            
            member_offset = base_offset + member.soff
            member_name = ida_struct.get_member_name(member.id)
            
            if not member_name:
                member_name = f"field_{hex(member.soff)}"
            
            full_name = f"{prefix}{member_name}"
            
            # 获取成员类型
            member_tif = ida_typeinf.tinfo_t()
            if not ida_struct.get_member_tinfo(member_tif, member):
                # 无法获取类型信息，使用默认大小
                member_size = member.eoff - member.soff
            else:
                member_size = member_tif.get_size()
            
            # 检查是否为嵌套结构体
            if member_tif.is_struct():
                # 递归处理嵌套结构体
                nested_name = member_tif.dstr()
                nested_slots = flatten_struct(
                    nested_name, 
                    binary_hash, 
                    member_offset, 
                    f"{full_name}."
                )
                slots.extend(nested_slots)
            else:
                # 基础类型成员，创建DataSlot
                slot_uid = hashlib.md5(
                    f"{struct_name}_{int(member_offset)}".encode('utf-8')
                ).hexdigest()
                
                slot = DataSlot(
                    uid=slot_uid,
                    base_type=struct_name,
                    offset=member_offset,
                    size=member_size,
                    name=full_name,
                    is_global=False
                )
                slots.append(slot)
    
    except Exception as e:
        # 结构体信息不完整，返回空列表
        pass
    
    return slots


def analyze_function_dataflow(func_ea: int, func_uid: str, 
                               binary_hash: str) -> Tuple[List[Dict], List[Dict], List[DataSlot]]:
    """
    分析单个函数的数据流
    
    Args:
        func_ea: 函数起始地址
        func_uid: 函数唯一ID
        binary_hash: 二进制文件hash
        
    Returns:
        (writes_edges, reads_edges, dataslots)
        - writes_edges: WRITES边列表
        - reads_edges: READS边列表
        - dataslots: 识别到的DataSlot对象列表
    """
    try:
        # 反编译函数
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return [], [], []
        
        # 创建visitor
        visitor = DataFlowVisitor(func_ea, func_uid, binary_hash)
        
        # 遍历ctree
        visitor.apply_to(cfunc.body, None)
        
        # 返回结果
        return visitor.writes, visitor.reads, visitor.get_dataslots()
    
    except ida_hexrays.DecompilationFailure as e:
        # 反编译失败
        print(f"[!] Decompilation failed for function at {hex(func_ea)}: {e}")
        return [], [], []
    
    except Exception as e:
        # 其他错误
        print(f"[!] Error analyzing function at {hex(func_ea)}: {e}")
        return [], [], []


# ====== 测试函数 ======

def test_dataflow_analyzer():
    """
    测试数据流分析器
    
    使用方法：
    1. 在IDA中打开二进制文件
    2. 运行: exec(open('analyzers/dataflow_analyzer.py').read())
    3. 运行: test_dataflow_analyzer()
    """
    print("=" * 60)
    print("Testing DataFlow Analyzer")
    print("=" * 60)
    
    # 获取当前IDB的二进制hash（简化版，实际应使用文件内容hash）
    binary_hash = "test_binary_hash_12345"
    
    # 测试：提取所有DataSlot
    print("\n[1] Extracting all DataSlots...")
    all_slots = extract_all_dataslots(binary_hash)
    print(f"    Found {len(all_slots)} DataSlots")
    
    # 显示前5个
    for slot in all_slots[:5]:
        print(f"    - {slot.name} ({slot.base_type}+{hex(slot.offset)})")
    
    # 测试：分析前10个函数
    print("\n[2] Analyzing functions...")
    func_count = 0
    total_writes = 0
    total_reads = 0
    
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        func_uid = f"test_func_{hex(func_ea)}"
        
        writes, reads, slots = analyze_function_dataflow(func_ea, func_uid, binary_hash)
        
        if writes or reads:
            print(f"\n    Function: {func_name} @ {hex(func_ea)}")
            print(f"      - WRITES: {len(writes)}")
            print(f"      - READS:  {len(reads)}")
            
            # 显示详细信息
            if writes:
                w = writes[0]
                print(f"        Example WRITE: {w['op_type']} -> DataSlot {w['to'][:8]}... (const: {w['const_val']})")
            
            if reads:
                r = reads[0]
                print(f"        Example READ: Condition={r['condition']}, Type={r['op_type']}")
            
            total_writes += len(writes)
            total_reads += len(reads)
            func_count += 1
        
        if func_count >= 10:
            break
    
    print("\n" + "=" * 60)
    print(f"Summary: Analyzed {func_count} functions")
    print(f"  Total WRITES edges: {total_writes}")
    print(f"  Total READS edges:  {total_reads}")
    print("=" * 60)


if __name__ == '__main__':
    # 如果在IDA环境中直接运行此脚本
    if 'idaapi' in dir():
        test_dataflow_analyzer()
