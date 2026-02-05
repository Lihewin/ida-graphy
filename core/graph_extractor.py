"""
Graph Extractor
图数据提取器 - 从IDA数据库中提取符合Neo4j模型的节点和边
"""

import os
import logging
import hashlib
from typing import Tuple, List, Dict, Optional
from tqdm import tqdm

# IDA SDK imports
import ida_funcs
import ida_nalt
import ida_segment
import ida_bytes
import ida_entry
import idautils
import idc
import ida_xref
import idaapi
import ida_typeinf

# 内部导入
from .node_id_generator import NodeIDGenerator
from .struct_normalizer import StructNameNormalizer
from .models import (
    GraphData, BinaryNode, FunctionNode, DataSlotNode, StringNode,
    ContainsEdge, CallsEdge, ReferencesEdge, LinksToEdge, WritesEdge, ReadsEdge
)

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class GraphExtractor:
    """
    图数据提取器
    
    从IDA数据库中提取符合Neo4j模型的节点和边。
    这是不包含数据流分析的基础版本（WRITES/READS边将由数据流分析模块完成）。
    """
    
    def __init__(self, binary_content: bytes, binary_path: str, struct_normalizer: StructNameNormalizer = None):
        """
        初始化提取器
        
        Args:
            binary_content: 二进制文件的完整内容
            binary_path: 二进制文件路径
            struct_normalizer: 结构体名称规范化器（可选）
        """
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path)
        self.id_gen = NodeIDGenerator(binary_content=binary_content)
        self.struct_normalizer = struct_normalizer or StructNameNormalizer()
        self.graph_data = GraphData()
        self.graph_data.binary_name = self.binary_name  # For symbol resolution
        
        # 缓存：用于快速查找
        self._func_id_cache = {}  # {func_ea: func_uid}
        self._string_id_cache = {}  # {string_content: string_hash}
        self._string_ea_cache = {}  # {string_ea: string_hash}
        self._export_table = None  # 导出表缓存
        
        logger.info(f"GraphExtractor initialized for: {self.binary_name}")
    
    # ============= 节点提取方法 =============
    
    def extract_binary_node(self) -> BinaryNode:
        """
        提取 Binary 节点
        
        使用 ida_nalt 获取文件信息
        
        Returns:
            BinaryNode 对象
        """
        logger.info("Extracting Binary node...")
        
        try:
            # 获取基本信息
            binary_hash = self.id_gen.get_binary_id()
            base_addr = ida_nalt.get_imagebase()
            
            # 获取架构信息 - 使用更简单的方式
            try:
                # 尝试获取处理器名称
                proc_name = idaapi.inf_get_procname()
                is_64 = idaapi.inf_is_64bit()
                is_32 = idaapi.inf_is_32bit_exactly()
                
                if is_64:
                    arch = "x86_64" if "metapc" in proc_name.lower() or "pc" in proc_name.lower() else "ARM64"
                elif is_32:
                    arch = "x86" if "metapc" in proc_name.lower() or "pc" in proc_name.lower() or "80" in proc_name else "ARM"
                else:
                    arch = proc_name
            except:
                # 备用方案：使用IDA的位宽函数
                if idc.get_inf_attr(idc.INF_64BIT):
                    arch = "x86_64"
                else:
                    arch = "x86"
            
            # 获取编译时间戳（PE文件特有）
            compile_ts = 0
            try:
                # 尝试从PE头获取
                pe_header = ida_nalt.get_imagebase() + 0x3C
                if idc.get_wide_dword(pe_header):
                    pe_offset = idc.get_wide_dword(pe_header)
                    compile_ts = idc.get_wide_dword(ida_nalt.get_imagebase() + pe_offset + 8)
            except:
                pass
            
            binary_node = BinaryNode(
                hash=binary_hash,
                name=self.binary_name,
                orig_name=self.binary_name,
                base_addr=base_addr,
                arch=arch,
                compile_ts=compile_ts
            )
            
            self.graph_data.binaries.append(binary_node)
            logger.info(f"Binary node created: {self.binary_name} ({arch})")
            
            return binary_node
            
        except Exception as e:
            logger.error(f"Failed to extract Binary node: {e}")
            raise
    
    def extract_function_nodes(self) -> List[FunctionNode]:
        """
        提取所有 Function 节点
        
        遍历所有函数，分类 func_type: NORMAL/IMPORT/EXPORT/THUNK
        提取签名、大小、复杂度
        
        Returns:
            FunctionNode 对象列表
        """
        logger.info("Extracting Function nodes...")
        
        function_nodes = []
        binary_id = self.id_gen.get_binary_id()
        
        # 获取导出表（缓存）
        if self._export_table is None:
            self._export_table = self._build_export_table()
        
        # 遍历所有函数
        func_list = list(idautils.Functions())
        logger.info(f"Found {len(func_list)} functions")
        
        for func_ea in tqdm(func_list, desc="Processing functions"):
            try:
                func_obj = ida_funcs.get_func(func_ea)
                if not func_obj:
                    continue
                
                # 计算RVA
                rva = func_ea - ida_nalt.get_imagebase()
                func_uid = self.id_gen.get_function_id(rva)
                
                # 缓存函数ID
                self._func_id_cache[func_ea] = func_uid
                
                # 获取函数名
                func_name = idc.get_func_name(func_ea)
                if not func_name:
                    func_name = f"sub_{rva:X}"
                
                # 分类函数类型
                func_type = self._classify_function(func_ea, func_obj)
                
                # 计算大小
                func_size = func_obj.end_ea - func_obj.start_ea
                
                # 获取函数签名
                signature = self._get_function_signature(func_ea)
                
                # 判断是否为库函数
                is_lib = self._is_library_function(func_ea, func_name)
                
                # 计算圈复杂度（简化版本）
                complexity = self._calculate_complexity(func_obj)
                
                function_node = FunctionNode(
                    uid=func_uid,
                    rva=rva,
                    name=func_name,
                    orig_name=func_name,
                    size=func_size,
                    is_lib=is_lib,
                    func_type=func_type,
                    signature=signature,
                    complexity=complexity,
                    binary_id=binary_id
                )
                
                function_nodes.append(function_node)
                self.graph_data.functions.append(function_node)
                
            except Exception as e:
                logger.warning(f"Failed to extract function at 0x{func_ea:X}: {e}")
                continue
        
        logger.info(f"Extracted {len(function_nodes)} Function nodes")
        return function_nodes
    
    def extract_string_nodes(self) -> List[StringNode]:
        """
        提取 String 节点
        
        使用 idautils.Strings() 获取所有字符串
        
        Returns:
            StringNode 对象列表
        """
        logger.info("Extracting String nodes...")
        
        string_nodes = []
        seen_strings = set()  # 去重
        
        try:
            strings = idautils.Strings()
            string_list = list(strings)
            logger.info(f"Found {len(string_list)} strings")
            
            for s in tqdm(string_list, desc="Processing strings"):
                try:
                    raw_content = str(s)
                    content = raw_content
                    
                    # 清洗字符串（去除不可打印字符）
                    content = self._clean_string(content)
                    
                    # 跳过过短或空字符串
                    if len(content) < 2 or not content.strip():
                        continue
                    
                    # 去重
                    if content in seen_strings:
                        continue
                    seen_strings.add(content)
                    
                    # 生成字符串ID
                    string_hash = self.id_gen.get_string_id(content)
                    self._string_id_cache[content] = string_hash
                    # 缓存地址映射用于REFERENCES提取
                    self._string_ea_cache[s.ea] = string_hash
                    
                    # 判断编码 - 使用 is_1_byte_encoding() 和 strtype
                    # strtype可能的值: STRTYPE_C, STRTYPE_C_16, STRTYPE_C_32 等
                    try:
                        if hasattr(s, 'is_1_byte_encoding'):
                            is_single_byte = s.is_1_byte_encoding()
                            encoding = "ASCII" if is_single_byte else "UTF-16"
                        elif hasattr(s, 'strtype'):
                            # 根据 strtype 判断编码
                            # STRTYPE_C (0) = C-style string, STRTYPE_C_16 = UTF-16, etc.
                            encoding = "UTF-16" if s.strtype in [1, 2, 3] else "ASCII"
                        else:
                            encoding = "ASCII"
                    except:
                        encoding = "ASCII"
                    
                    string_node = StringNode(
                        hash=string_hash,
                        content=content,
                        orig_name=raw_content,
                        encoding=encoding
                    )
                    
                    string_nodes.append(string_node)
                    self.graph_data.strings.append(string_node)
                    
                except Exception as e:
                    logger.warning(f"Failed to extract string: {e}")
                    continue
            
            logger.info(f"Extracted {len(string_nodes)} String nodes")
            
        except Exception as e:
            logger.error(f"Failed to extract strings: {e}")
        
        return string_nodes
    
    def extract_dataslot_nodes(self) -> List[DataSlotNode]:
        """
        提取 DataSlot 节点
        
        遍历所有命名地址，识别数据段中的全局变量
        遍历所有结构体，提取结构体成员
        
        Returns:
            DataSlotNode 对象列表
        """
        logger.info("Extracting DataSlot nodes...")
        dataslot_nodes = []
        
        try:
            # ============= 1. 提取全局变量 =============
            # 统计数据段数量
            data_segments = []
            for seg_ea in idautils.Segments():
                seg = ida_segment.getseg(seg_ea)
                if seg and seg.type == ida_segment.SEG_DATA:
                    seg_name = ida_segment.get_segm_name(seg)
                    data_segments.append(seg_name)
            
            logger.info(f"Found {len(data_segments)} data segments: {', '.join(data_segments)}")
            
            # 遍历所有命名地址，过滤数据段中的地址
            names_list = list(idautils.Names())
            logger.info(f"Scanning {len(names_list)} named addresses for globals...")
            
            data_items = 0
            for ea, name in tqdm(names_list, desc="Processing globals"):
                try:
                    # 获取地址所在的段
                    seg = ida_segment.getseg(ea)
                    if not seg:
                        continue
                    
                    # 只处理数据段(SEG_DATA)，排除代码段(SEG_CODE)
                    if seg.type != ida_segment.SEG_DATA:
                        continue
                    
                    data_items += 1
                    
                    # 获取数据项大小
                    size = ida_bytes.get_item_size(ea)
                    if size == 0:
                        continue
                    
                    # 获取RVA（相对虚拟地址）
                    base_addr = ida_nalt.get_imagebase()
                    rva = ea - base_addr
                    
                    # 生成DataSlot节点（全局变量）
                    dataslot_uid = self.id_gen.get_global_slot_id(rva)
                    
                    dataslot_node = DataSlotNode(
                        uid=dataslot_uid,
                        base_type='GLOBAL',
                        base_type_orig='GLOBAL',
                        offset=rva,
                        size=size,
                        name=name,
                        orig_name=name,
                        is_global=True
                    )
                    
                    dataslot_nodes.append(dataslot_node)
                    self.graph_data.dataslots.append(dataslot_node)
                    
                except Exception as e:
                    logger.warning(f"Failed to extract global at {hex(ea)}: {e}")
                    continue
            
            logger.info(f"Found {data_items} global variables in data segments")
            
            # ============= 2. 提取结构体成员 =============
            structs_list = list(idautils.Structs())
            logger.info(f"Found {len(structs_list)} structures, extracting members...")
            
            struct_members = 0
            for struct_idx, struct_id, struct_name in tqdm(structs_list, desc="Processing structures"):
                try:
                    if not struct_name:
                        continue
                    
                    # 获取结构体成员
                    members = list(idautils.StructMembers(struct_id))
                    
                    for member_offset, member_name, member_size in members:
                        try:
                            orig_member_name = member_name or ""
                            display_name = member_name or f"field_{member_offset:X}"
                            
                            # 规范化结构体名称（实现跨二进制一致性）
                            normalized_struct_name = self.struct_normalizer.normalize(struct_name)
                            
                            # 生成DataSlot节点（结构体成员）
                            # 使用规范化后的结构体名+偏移量生成跨二进制一致的ID
                            dataslot_uid = self.id_gen.get_struct_slot_id(normalized_struct_name, member_offset)
                            
                            dataslot_node = DataSlotNode(
                                uid=dataslot_uid,
                                base_type=normalized_struct_name,  # 使用规范化后的名称
                                base_type_orig=struct_name,
                                offset=member_offset,
                                size=member_size,
                                name=display_name,
                                orig_name=orig_member_name,
                                is_global=False
                            )
                            
                            dataslot_nodes.append(dataslot_node)
                            self.graph_data.dataslots.append(dataslot_node)
                            struct_members += 1
                            
                        except Exception as e:
                            logger.warning(f"Failed to extract member {member_name} from {struct_name}: {e}")
                            continue
                
                except Exception as e:
                    logger.warning(f"Failed to process structure {struct_name}: {e}")
                    continue
            
            logger.info(f"Extracted {struct_members} structure members")
            logger.info(f"Total DataSlot nodes: {len(dataslot_nodes)} (Globals: {data_items}, Struct members: {struct_members})")
            
        except Exception as e:
            logger.error(f"Failed to extract dataslots: {e}")
        
        return dataslot_nodes
    
    # ============= 边提取方法 =============
    
    def extract_contains_edges(self) -> List[ContainsEdge]:
        """
        提取 CONTAINS 边
        
        Binary 与其他节点的归属关系：
        - Binary -> Function
        - Binary -> String
        - Binary -> DataSlot (全局变量)
        
        Returns:
            ContainsEdge 对象列表
        """
        logger.info("Extracting CONTAINS edges...")
        
        contains_edges = []
        binary_id = self.id_gen.get_binary_id()
        
        # Binary -> Function
        for func in self.graph_data.functions:
            edge = ContainsEdge(from_id=binary_id, to_id=func.uid)
            contains_edges.append(edge)
            self.graph_data.contains.append(edge)
        
        # Binary -> String
        for string in self.graph_data.strings:
            edge = ContainsEdge(from_id=binary_id, to_id=string.hash)
            contains_edges.append(edge)
            self.graph_data.contains.append(edge)
        
        # Binary -> DataSlot
        for dataslot in self.graph_data.dataslots:
            edge = ContainsEdge(from_id=binary_id, to_id=dataslot.uid)
            contains_edges.append(edge)
            self.graph_data.contains.append(edge)
        
        logger.info(f"Extracted {len(contains_edges)} CONTAINS edges")
        return contains_edges
    
    def extract_call_edges(self) -> List[CallsEdge]:
        """
        提取 CALLS 边
        
        函数调用关系，使用 idautils.XrefsFrom 分析调用指令
        
        Returns:
            CallsEdge 对象列表
        """
        logger.info("Extracting CALLS edges...")
        
        call_edges = []
        base_addr = ida_nalt.get_imagebase()
        
        for func in tqdm(self.graph_data.functions, desc="Analyzing calls"):
            try:
                func_ea = ida_nalt.get_imagebase() + func.rva
                func_obj = ida_funcs.get_func(func_ea)
                if not func_obj:
                    continue

                seq_order = 0
                
                # 遍历函数中的所有指令
                for head in idautils.FuncItems(func_ea):
                    # 查找调用引用
                    for xref in idautils.XrefsFrom(head, 0):
                        # 只处理代码流引用（调用）
                        if xref.type not in [ida_xref.fl_CF, ida_xref.fl_CN]:
                            continue
                        
                        callee_ea = xref.to
                        callee_func = ida_funcs.get_func(callee_ea)
                        if not callee_func:
                            continue
                        
                        # 获取被调用函数的ID
                        callee_start = callee_func.start_ea
                        if callee_start not in self._func_id_cache:
                            continue
                        
                        callee_uid = self._func_id_cache[callee_start]
                        
                        # 判断调用类型
                        call_type = self._detect_call_type(head, xref)
                        
                        edge = CallsEdge(
                            from_id=func.uid,
                            to_id=callee_uid,
                            call_type=call_type,
                            count=1,
                            loc=head - base_addr,
                            seq_order=seq_order,
                        )
                        call_edges.append(edge)
                        self.graph_data.calls.append(edge)
                        seq_order += 1
                
            except Exception as e:
                logger.warning(f"Failed to analyze calls for {func.name}: {e}")
                continue
        
        logger.info(f"Extracted {len(call_edges)} CALLS edges")
        return call_edges
    
    def extract_reference_edges(self) -> List[ReferencesEdge]:
        """
        提取 REFERENCES 边
        
        函数引用字符串的关系
        
        Returns:
            ReferencesEdge 对象列表
        """
        logger.info("Extracting REFERENCES edges...")
        
        reference_edges = []
        
        # 遍历每个函数，分析其指令的操作数
        for func in tqdm(self.graph_data.functions, desc="Analyzing string refs"):
            try:
                func_ea = ida_nalt.get_imagebase() + func.rva
                func_obj = ida_funcs.get_func(func_ea)
                if not func_obj:
                    continue
                
                # 遍历函数中的所有指令
                for head in idautils.FuncItems(func_ea):
                    # 检查指令的操作数
                    for i in range(2):  # 大多数指令最多2个操作数
                        op_type = idc.get_operand_type(head, i)
                        # o_mem (2) = 直接内存引用, o_imm (5) = 立即数（可能是地址）
                        if op_type in [idc.o_mem, idc.o_imm]:
                            op_value = idc.get_operand_value(head, i)
                            # 检查操作数值是否为字符串地址
                            if op_value in self._string_ea_cache:
                                string_hash = self._string_ea_cache[op_value]
                                
                                edge = ReferencesEdge(
                                    from_id=func.uid,
                                    to_id=string_hash
                                )
                                reference_edges.append(edge)
                                self.graph_data.references.append(edge)
                
            except Exception as e:
                logger.warning(f"Failed to analyze references for {func.name}: {e}")
                continue
        
        logger.info(f"Extracted {len(reference_edges)} REFERENCES edges")
        return reference_edges
    
    def extract_links_to_edges(self) -> List[LinksToEdge]:
        """
        提取 LINKS_TO 边
        
        连接当前二进制的IMPORT函数到外部库的EXPORT函数
        
        Returns:
            LinksToEdge 对象列表
        """
        logger.info("Extracting LINKS_TO edges...")
        
        links_to_edges = []
        import_count = 0
        
        try:
            # 遍历导入表
            nimps = ida_nalt.get_import_module_qty()
            logger.info(f"Found {nimps} import modules")
            
            for i in range(nimps):
                module_name = ida_nalt.get_import_module_name(i)
                if not module_name:
                    continue
                
                # 枚举模块中的导入函数
                def import_callback(ea, name, ordinal):
                    nonlocal import_count
                    if not ea or ea == idaapi.BADADDR:
                        return True
                    
                    import_count += 1
                    
                    # 为导入函数生成UID（基于其RVA）
                    base_addr = ida_nalt.get_imagebase()
                    import_rva = ea - base_addr
                    import_func_uid = self.id_gen.get_function_id(import_rva)
                    
                    # 为外部函数生成虚拟UID (使用模块名+函数名)
                    # 注意：这是虚拟节点，实际的EXPORT节点需要分析目标DLL才能获得
                    if name:
                        # 外部函数使用特殊ID方案
                        external_id = hashlib.md5(f"{module_name}!{name}".encode()).hexdigest()
                        
                        edge = LinksToEdge(
                            from_id=import_func_uid,
                            to_id=external_id,
                            dll_name=module_name,
                            func_name=name
                        )
                        links_to_edges.append(edge)
                        self.graph_data.links_to.append(edge)
                    
                    return True
                
                ida_nalt.enum_import_names(i, import_callback)
            
            logger.info(f"Found {import_count} imports, extracted {len(links_to_edges)} LINKS_TO edges")
            
        except Exception as e:
            logger.error(f"Failed to extract LINKS_TO edges: {e}")
        
        return links_to_edges
    
    def extract_dataflow_edges(self):
        """
        提取数据流边（WRITES/READS）- 简化版本
        
        通过指令分析识别内存读写操作，不依赖Hex-Rays反编译器
        
        Returns:
            (writes_edges, reads_edges) - WRITES 和 READS 边列表
        """
        logger.info("Extracting dataflow edges (simplified version)...")
        
        writes_edges = []
        reads_edges = []
        
        # 创建DataSlot地址映射
        dataslot_ea_map = {}  # {ea: dataslot_uid}
        for ds in self.graph_data.dataslots:
            ea = ida_nalt.get_imagebase() + ds.offset
            dataslot_ea_map[ea] = ds.uid
        
        if len(dataslot_ea_map) == 0:
            logger.info("No DataSlots to analyze")
            return writes_edges, reads_edges
        
        logger.info(f"Analyzing {len(self.graph_data.functions)} functions for dataflow...")
        
        for func in tqdm(self.graph_data.functions, desc="Analyzing dataflow"):
            try:
                func_ea = ida_nalt.get_imagebase() + func.rva
                func_obj = ida_funcs.get_func(func_ea)
                if not func_obj:
                    continue
                
                # 遍历函数中的所有指令
                for head in idautils.FuncItems(func_ea):
                    mnem = idc.print_insn_mnem(head).lower()
                    
                    # 分析写操作
                    if mnem in ['mov', 'movzx', 'movsx', 'lea', 'xor', 'or', 'and', 'add', 'sub', 'inc', 'dec']:
                        # 检查目标操作数（通常是第一个）
                        op0_type = idc.get_operand_type(head, 0)
                        if op0_type == idc.o_mem:  # 内存操作数
                            target_ea = idc.get_operand_value(head, 0)
                            if target_ea in dataslot_ea_map:
                                # 确定操作类型
                                if mnem in ['mov', 'movzx', 'movsx', 'lea']:
                                    op_type = 'ASSIGN'
                                elif mnem == 'or':
                                    op_type = 'OR'
                                elif mnem == 'and':
                                    op_type = 'AND'
                                elif mnem in ['add', 'inc']:
                                    op_type = 'ADD'
                                else:
                                    op_type = 'ASSIGN'
                                
                                # 尝试获取常量值
                                const_val = None
                                op1_type = idc.get_operand_type(head, 1)
                                if op1_type == idc.o_imm:
                                    const_val = hex(idc.get_operand_value(head, 1))
                                
                                edge = WritesEdge(
                                    from_id=func.uid,
                                    to_id=dataslot_ea_map[target_ea],
                                    op_type=op_type,
                                    loc=head - ida_nalt.get_imagebase(),
                                    const_val=const_val
                                )
                                writes_edges.append(edge)
                                self.graph_data.writes.append(edge)
                    
                    # 分析读操作
                    # 检查所有源操作数
                    for op_idx in [0, 1, 2]:
                        op_type = idc.get_operand_type(head, op_idx)
                        if op_type == idc.o_mem:
                            source_ea = idc.get_operand_value(head, op_idx)
                            if source_ea in dataslot_ea_map:
                                # 判断是否在条件指令中
                                is_condition = mnem in ['cmp', 'test', 'jz', 'jnz', 'je', 'jne', 'jg', 'jl', 'jge', 'jle']
                                
                                # 获取常量值（用于比较）
                                const_val = None
                                if mnem in ['cmp', 'test']:
                                    other_op_idx = 1 if op_idx == 0 else 0
                                    other_op_type = idc.get_operand_type(head, other_op_idx)
                                    if other_op_type == idc.o_imm:
                                        const_val = hex(idc.get_operand_value(head, other_op_idx))
                                
                                edge = ReadsEdge(
                                    from_id=func.uid,
                                    to_id=dataslot_ea_map[source_ea],
                                    condition=is_condition,
                                    loc=head - ida_nalt.get_imagebase(),
                                    op_type=mnem.upper(),
                                    const_val=const_val
                                )
                                reads_edges.append(edge)
                                self.graph_data.reads.append(edge)
            
            except Exception as e:
                logger.warning(f"Failed to analyze dataflow for {func.name}: {e}")
                continue
        
        logger.info(f"Extracted {len(writes_edges)} WRITES edges")
        logger.info(f"Extracted {len(reads_edges)} READS edges")
        return writes_edges, reads_edges
    
    # ============= 辅助方法 =============
    
    def _build_export_table(self) -> set:
        """构建导出表缓存"""
        export_set = set()
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            if ea != idc.BADADDR:
                export_set.add(ea)
        return export_set
    
    def _classify_function(self, func_ea: int, func_obj) -> str:
        """
        分类函数类型：NORMAL/IMPORT/EXPORT/THUNK
        
        基于改造.md中的分类逻辑
        """
        # 1. 检查是否在导出表
        if func_ea in self._export_table:
            return "EXPORT"
        
        # 2. 检查是否为 Thunk 类型
        flags = func_obj.flags
        if flags & ida_funcs.FUNC_THUNK:
            # 判断是否为导入桩
            func_name = idc.get_func_name(func_ea)
            if "__imp_" in func_name or self._is_in_import_section(func_ea):
                return "IMPORT"
            return "THUNK"
        
        # 3. 检查是否为外部函数（导入）
        if flags & ida_funcs.FUNC_LIB:
            return "IMPORT"
        
        # 4. 默认为普通业务函数
        return "NORMAL"
    
    def _is_in_import_section(self, ea: int) -> bool:
        """判断地址是否在导入表段"""
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            return seg_name in [".idata", ".rdata", "__imp__"]
        return False
    
    def _get_function_signature(self, func_ea: int) -> str:
        """获取函数签名"""
        try:
            func_type = idc.get_type(func_ea)
            if func_type:
                return func_type
        except:
            pass
        return ""
    
    def _is_library_function(self, func_ea: int, func_name: str) -> bool:
        """判断是否为库函数"""
        # 简单启发式：检查函数名前缀
        lib_prefixes = ["__", "_imp_", "std::", "operator"]
        for prefix in lib_prefixes:
            if func_name.startswith(prefix):
                return True
        
        # 检查函数标志
        func = ida_funcs.get_func(func_ea)
        if func and (func.flags & ida_funcs.FUNC_LIB):
            return True
        
        return False
    
    def _calculate_complexity(self, func_obj) -> int:
        """
        计算圈复杂度（简化版本）
        
        基于基本块数量的估算
        """
        try:
            # 统计条件跳转和函数调用
            complexity = 1
            for head in idautils.FuncItems(func_obj.start_ea):
                mnem = idc.print_insn_mnem(head)
                # 条件跳转增加复杂度
                if mnem.startswith("j") and mnem not in ["jmp"]:
                    complexity += 1
            return complexity
        except:
            return 1
    
    def _clean_string(self, s: str) -> str:
        """清洗字符串，去除不可打印字符"""
        return ''.join(c if c.isprintable() else ' ' for c in s).strip()
    
    def _detect_call_type(self, insn_ea: int, xref) -> str:
        """检测调用类型：DIRECT/INDIRECT/TAIL"""
        mnem = idc.print_insn_mnem(insn_ea)
        
        # 间接调用
        if mnem in ["call", "jmp"]:
            # 检查操作数是否为寄存器或内存
            op_type = idc.get_operand_type(insn_ea, 0)
            if op_type in [idc.o_reg, idc.o_phrase, idc.o_displ]:
                return "INDIRECT"
        
        # 尾调用
        if mnem == "jmp":
            return "TAIL"
        
        return "DIRECT"
    
    def _get_string_at(self, ea: int) -> Optional[str]:
        """尝试在指定地址获取字符串"""
        try:
            # 尝试获取字符串
            string_type = idc.get_str_type(ea)
            if string_type is not None:
                content = idc.get_strlit_contents(ea)
                if content:
                    return content.decode('utf-8', errors='ignore')
        except:
            pass
        return None
    
    # ============= 主提取方法 =============
    
    def extract_all(self) -> GraphData:
        """
        执行完整的图数据提取流程
        
        Returns:
            GraphData 对象，包含所有节点和边
        """
        logger.info("=" * 60)
        logger.info("Starting graph extraction...")
        logger.info("=" * 60)
        
        try:
            # 1. 提取节点
            self.extract_binary_node()
            self.extract_function_nodes()
            self.extract_string_nodes()
            self.extract_dataslot_nodes()  # 暂未实现
            
            # 2. 提取边
            self.extract_contains_edges()
            self.extract_call_edges()
            self.extract_links_to_edges()
            self.extract_reference_edges()
            self.extract_dataflow_edges()
            
            # 3. 统计信息
            logger.info("=" * 60)
            logger.info("Extraction completed!")
            logger.info(f"Nodes: {self.graph_data.node_count()}")
            logger.info(f"  - Binary: {len(self.graph_data.binaries)}")
            logger.info(f"  - Function: {len(self.graph_data.functions)}")
            logger.info(f"  - DataSlot: {len(self.graph_data.dataslots)}")
            logger.info(f"  - String: {len(self.graph_data.strings)}")
            logger.info(f"Edges: {self.graph_data.edge_count()}")
            logger.info(f"  - CONTAINS: {len(self.graph_data.contains)}")
            logger.info(f"  - CALLS: {len(self.graph_data.calls)}")
            logger.info(f"  - LINKS_TO: {len(self.graph_data.links_to)}")
            logger.info(f"  - REFERENCES: {len(self.graph_data.references)}")
            logger.info(f"  - WRITES: {len(self.graph_data.writes)}")
            logger.info(f"  - READS: {len(self.graph_data.reads)}")
            logger.info("=" * 60)
            
            return self.graph_data
            
        except Exception as e:
            logger.error(f"Graph extraction failed: {e}")
            raise
