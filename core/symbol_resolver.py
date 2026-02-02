"""
Symbol Resolver
===============

跨二进制符号解析器，用于将LINKS_TO边的虚拟外部函数ID替换为真实的EXPORT函数ID。

工作流程：
1. 收集所有EXPORT函数：{(dll_name, func_name): func_uid}
2. 遍历LINKS_TO边，解析虚拟ID（"DLL!函数"格式）
3. 如果找到匹配的EXPORT函数，更新to_id

这样可以实现设计文档中的：
(:Function {type:'IMPORT'}) -[:LINKS_TO]-> (:Function {type:'EXPORT'})
"""

import hashlib
import logging
from typing import Dict, List, Tuple, Optional
from .models import LinksToEdge, FunctionNode

logger = logging.getLogger(__name__)


class SymbolResolver:
    """跨二进制符号解析器"""
    
    def __init__(self):
        """初始化解析器"""
        self.export_table: Dict[str, str] = {}  # {("kernel32.dll", "CreateFileW"): func_uid}
        self.resolved_count = 0
        self.unresolved_count = 0
    
    def build_export_table(self, functions: List[FunctionNode], binary_name: str) -> None:
        """
        构建导出表
        
        Args:
            functions: 函数节点列表
            binary_name: 二进制文件名（用作DLL名，如"kernel32.dll"）
        """
        # 规范化DLL名称（小写，确保有.dll后缀）
        dll_name = binary_name.lower()
        if not dll_name.endswith('.dll') and not dll_name.endswith('.exe'):
            # 如果没有后缀，尝试添加.dll
            dll_name = dll_name + '.dll'
        
        export_count = 0
        for func in functions:
            if func.func_type == 'EXPORT':
                key = (dll_name, func.name)
                self.export_table[key] = func.uid
                export_count += 1
        
        if export_count > 0:
            logger.info(f"Added {export_count} exports from {dll_name}")
    
    def resolve_links_to_edges(self, edges: List[LinksToEdge]) -> List[LinksToEdge]:
        """
        解析LINKS_TO边，将虚拟外部ID替换为真实EXPORT函数ID
        
        Args:
            edges: LINKS_TO边列表
        
        Returns:
            更新后的LINKS_TO边列表
        """
        if len(self.export_table) == 0:
            logger.info("No EXPORT functions available, skipping symbol resolution")
            return edges
        
        logger.info(f"Resolving {len(edges)} LINKS_TO edges against {len(self.export_table)} exports...")
        
        resolved_edges = []
        
        for edge in edges:
            # 从边中获取DLL名和函数名
            dll_func = self._reverse_lookup_virtual_id(edge)
            
            if dll_func:
                dll_name, func_name = dll_func
                
                # 尝试多种DLL名称变体匹配
                real_func_uid = None
                for variant in self._get_dll_name_variants(dll_name):
                    key = (variant, func_name)
                    if key in self.export_table:
                        real_func_uid = self.export_table[key]
                        break
                
                if real_func_uid:
                    # 找到了！更新边
                    edge.to_id = real_func_uid
                    self.resolved_count += 1
                else:
                    self.unresolved_count += 1
            else:
                self.unresolved_count += 1
            
            resolved_edges.append(edge)
        
        logger.info(f"Symbol resolution completed:")
        logger.info(f"  - Resolved: {self.resolved_count}")
        logger.info(f"  - Unresolved: {self.unresolved_count} (external DLLs not in analysis)")
        
        return resolved_edges
    
    def _reverse_lookup_virtual_id(self, edge: LinksToEdge) -> Optional[Tuple[str, str]]:
        """
        从LinksToEdge边中获取DLL名和函数名
        
        Args:
            edge: LINKS_TO边（包含dll_name和func_name字段）
        
        Returns:
            (dll_name, func_name) 或 None
        """
        if edge.dll_name and edge.func_name:
            return (edge.dll_name, edge.func_name)
        return None
    
    def _get_dll_name_variants(self, dll_name: str) -> List[str]:
        """
        生成DLL名称的变体，用于匹配
        
        例如："kernel32" -> ["kernel32.dll", "kernel32", "KERNEL32.DLL"]
        
        Args:
            dll_name: 原始DLL名
        
        Returns:
            DLL名称变体列表
        """
        variants = [dll_name.lower()]
        
        # 添加.dll后缀变体
        if not dll_name.lower().endswith('.dll'):
            variants.append(dll_name.lower() + '.dll')
        else:
            # 移除.dll后缀变体
            variants.append(dll_name.lower().replace('.dll', ''))
        
        # 添加大写变体
        variants.append(dll_name.upper())
        if dll_name.lower().endswith('.dll'):
            variants.append(dll_name.upper().replace('.DLL', '.dll'))
        
        return list(set(variants))  # 去重


def resolve_symbols(all_functions: List[FunctionNode], 
                   all_links_to_edges: List[LinksToEdge],
                   binary_names: Dict[str, str]) -> List[LinksToEdge]:
    """
    全局符号解析入口函数
    
    Args:
        all_functions: 所有二进制的函数列表
        all_links_to_edges: 所有LINKS_TO边
        binary_names: {binary_hash: binary_name} 映射
    
    Returns:
        解析后的LINKS_TO边列表
    """
    resolver = SymbolResolver()
    
    # 按二进制分组函数，构建导出表
    binary_functions: Dict[str, List[FunctionNode]] = {}
    for func in all_functions:
        if func.binary_id not in binary_functions:
            binary_functions[func.binary_id] = []
        binary_functions[func.binary_id].append(func)
    
    # 为每个二进制构建导出表
    for binary_hash, functions in binary_functions.items():
        binary_name = binary_names.get(binary_hash, "unknown")
        resolver.build_export_table(functions, binary_name)
    
    # 解析LINKS_TO边
    resolved_edges = resolver.resolve_links_to_edges(all_links_to_edges)
    
    return resolved_edges
