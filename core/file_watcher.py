"""
File Change Detection and Monitoring

This module provides comprehensive file change detection capabilities for
ida-graphy projects. Supports both on-demand checking and continuous monitoring
for automatic project synchronization.

Key Features:
- SHA256-based file content change detection
- File modification time tracking for performance optimization  
- Batch change detection for multiple files
- File monitoring with configurable refresh intervals
- Integration with project management for automatic updates
- Graceful handling of missing or inaccessible files

Architecture:
- Uses same hashing algorithm as main ida_graphy.py for consistency
- Provides both synchronous and background monitoring modes
- Integrates seamlessly with ProjectManager for change reporting
- Supports file system event monitoring (optional)
"""

import hashlib
import os
import time
import logging
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Callable, Set
from pathlib import Path
import threading
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class FileStatus:
    """文件状态信息"""
    path: str               # 文件路径
    exists: bool           # 文件是否存在
    size: int              # 文件大小（字节）
    modified_time: float   # 修改时间（时间戳）
    hash: Optional[str]    # 文件哈希（如果计算了的话）
    error: Optional[str]   # 错误信息（如果有的话）


@dataclass
class FileChange:
    """文件变化信息"""
    path: str              # 文件路径
    change_type: str       # 变化类型：'added', 'modified', 'deleted', 'unchanged'
    old_hash: Optional[str] = None   # 旧哈希
    new_hash: Optional[str] = None   # 新哈希
    old_size: Optional[int] = None   # 旧大小
    new_size: Optional[int] = None   # 新大小
    detected_time: Optional[str] = None  # 检测时间（ISO格式）


class FileWatcher:
    """文件变化监控器"""
    
    def __init__(self, check_interval: float = 5.0):
        """
        初始化文件监控器
        
        Args:
            check_interval: 检查间隔（秒）
        """
        self.check_interval = check_interval
        self.monitored_files: Dict[str, FileStatus] = {}
        self.callbacks: List[Callable[[List[FileChange]], None]] = []
        
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def add_file(self, file_path: str) -> None:
        """
        添加文件到监控列表
        
        Args:
            file_path: 文件路径
        """
        file_path = os.path.abspath(file_path)
        status = self.get_file_status(file_path)
        self.monitored_files[file_path] = status
        logger.debug(f"添加文件到监控: {file_path}")
    
    def remove_file(self, file_path: str) -> None:
        """
        从监控列表中移除文件
        
        Args:
            file_path: 文件路径
        """
        file_path = os.path.abspath(file_path)
        if file_path in self.monitored_files:
            del self.monitored_files[file_path]
            logger.debug(f"从监控中移除文件: {file_path}")
    
    def add_callback(self, callback: Callable[[List[FileChange]], None]) -> None:
        """
        添加变化回调函数
        
        Args:
            callback: 回调函数，参数为FileChange列表
        """
        self.callbacks.append(callback)
    
    def start_monitoring(self) -> None:
        """开始后台监控"""
        if self._monitoring:
            logger.warning("文件监控已在运行中")
            return
        
        self._monitoring = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="FileWatcher",
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"开始文件监控，检查间隔: {self.check_interval}秒")
    
    def stop_monitoring(self) -> None:
        """停止后台监控"""
        if not self._monitoring:
            return
        
        self._monitoring = False
        self._stop_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)
            if self._monitor_thread.is_alive():
                logger.warning("监控线程未能正常停止")
        
        logger.info("文件监控已停止")
    
    def check_changes(self) -> List[FileChange]:
        """
        检查所有监控文件的变化
        
        Returns:
            文件变化列表
        """
        changes = []
        current_time = datetime.now().isoformat()
        
        for file_path, old_status in self.monitored_files.items():
            new_status = self.get_file_status(file_path)
            change = self._compare_status(file_path, old_status, new_status)
            
            if change.change_type != 'unchanged':
                change.detected_time = current_time
                changes.append(change)
                
                # 更新存储的状态
                self.monitored_files[file_path] = new_status
        
        return changes
    
    def _monitor_loop(self) -> None:
        """后台监控循环"""
        while self._monitoring and not self._stop_event.wait(self.check_interval):
            try:
                changes = self.check_changes()
                
                if changes:
                    logger.info(f"检测到 {len(changes)} 个文件变化")
                    
                    # 调用所有回调函数
                    for callback in self.callbacks:
                        try:
                            callback(changes)
                        except Exception as e:
                            logger.error(f"文件变化回调出错: {e}")
                
            except Exception as e:
                logger.error(f"文件监控出错: {e}")
    
    def _compare_status(self, file_path: str, old_status: FileStatus, 
                       new_status: FileStatus) -> FileChange:
        """
        比较文件状态并生成变化记录
        
        Args:
            file_path: 文件路径
            old_status: 旧状态
            new_status: 新状态
            
        Returns:
            文件变化信息
        """
        # 文件被删除
        if old_status.exists and not new_status.exists:
            return FileChange(
                path=file_path,
                change_type='deleted',
                old_hash=old_status.hash,
                old_size=old_status.size
            )
        
        # 文件被添加
        if not old_status.exists and new_status.exists:
            return FileChange(
                path=file_path,
                change_type='added',
                new_hash=new_status.hash,
                new_size=new_status.size
            )
        
        # 文件都存在，比较内容
        if old_status.exists and new_status.exists:
            # 快速检查：大小或修改时间变化
            if (old_status.size != new_status.size or 
                old_status.modified_time != new_status.modified_time):
                
                # 计算哈希以确认内容变化
                if old_status.hash is None:
                    old_status.hash = self.calculate_file_hash(file_path, use_cache=False)
                    
                if new_status.hash != old_status.hash:
                    return FileChange(
                        path=file_path,
                        change_type='modified',
                        old_hash=old_status.hash,
                        new_hash=new_status.hash,
                        old_size=old_status.size,
                        new_size=new_status.size
                    )
        
        # 文件未变化
        return FileChange(
            path=file_path,
            change_type='unchanged'
        )
    
    @staticmethod
    def get_file_status(file_path: str, calculate_hash: bool = True) -> FileStatus:
        """
        获取文件状态信息
        
        Args:
            file_path: 文件路径
            calculate_hash: 是否计算哈希
            
        Returns:
            文件状态信息
        """
        try:
            if not os.path.exists(file_path):
                return FileStatus(
                    path=file_path,
                    exists=False,
                    size=0,
                    modified_time=0,
                    hash=None,
                    error=None
                )
            
            stat = os.stat(file_path)
            file_hash = None
            
            if calculate_hash:
                file_hash = FileWatcher.calculate_file_hash(file_path)
            
            return FileStatus(
                path=file_path,
                exists=True,
                size=stat.st_size,
                modified_time=stat.st_mtime,
                hash=file_hash,
                error=None
            )
            
        except Exception as e:
            logger.error(f"获取文件状态失败: {file_path}, 错误: {e}")
            return FileStatus(
                path=file_path,
                exists=False,
                size=0,
                modified_time=0,
                hash=None,
                error=str(e)
            )
    
    @staticmethod
    def calculate_file_hash(file_path: str, use_cache: bool = True) -> Optional[str]:
        """
        计算文件SHA256哈希（与ida_graphy.py中的实现一致）
        
        Args:
            file_path: 文件路径
            use_cache: 是否使用缓存（当前未实现缓存）
            
        Returns:
            SHA256哈希字符串，失败返回None
        """
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        
        except Exception as e:
            logger.error(f"计算文件哈希失败: {file_path}, 错误: {e}")
            return None


class ProjectFileMonitor:
    """项目文件监控器，集成项目管理功能"""
    
    def __init__(self, project_manager, project_name: str, 
                 auto_sync: bool = False, sync_callback: Optional[Callable] = None):
        """
        初始化项目文件监控器
        
        Args:
            project_manager: ProjectManager实例
            project_name: 项目名称
            auto_sync: 是否自动同步变化到数据库
            sync_callback: 同步回调函数
        """
        self.project_manager = project_manager
        self.project_name = project_name
        self.auto_sync = auto_sync
        self.sync_callback = sync_callback
        
        self.file_watcher = FileWatcher()
        self.file_watcher.add_callback(self._on_files_changed)
        
        # 初始化监控文件列表
        self._update_monitored_files()
    
    def _update_monitored_files(self) -> None:
        """更新监控的文件列表"""
        try:
            project = self.project_manager.get_project(self.project_name)
            
            # 清空现有监控列表
            self.file_watcher.monitored_files.clear()
            
            # 添加项目中的所有文件
            for binary_file in project.binaries:
                self.file_watcher.add_file(binary_file.path)
            
            logger.info(f"项目 '{self.project_name}' 监控 {len(project.binaries)} 个文件")
            
        except Exception as e:
            logger.error(f"更新监控文件列表失败: {e}")
    
    def _on_files_changed(self, changes: List[FileChange]) -> None:
        """文件变化回调处理"""
        logger.info(f"项目 '{self.project_name}' 检测到文件变化:")
        
        for change in changes:
            logger.info(f"  {change.change_type}: {change.path}")
            
            # 更新项目中的文件信息
            try:
                if change.change_type == 'modified':
                    # 更新文件哈希等信息
                    self._update_binary_file_info(change.path, change.new_hash, change.new_size)
                elif change.change_type == 'deleted':
                    logger.warning(f"文件已删除: {change.path}")
                    
            except Exception as e:
                logger.error(f"更新文件信息失败: {e}")
        
        # 自动同步（如果启用）
        if self.auto_sync and self.sync_callback:
            try:
                modified_files = [c for c in changes if c.change_type == 'modified']
                if modified_files:
                    self.sync_callback(self.project_name, modified_files)
            except Exception as e:
                logger.error(f"自动同步失败: {e}")
    
    def _update_binary_file_info(self, file_path: str, new_hash: str, new_size: int) -> None:
        """更新二进制文件信息"""
        try:
            project = self.project_manager.get_project(self.project_name)
            
            for binary_file in project.binaries:
                if binary_file.path == file_path:
                    binary_file.hash = new_hash
                    binary_file.size = new_size
                    binary_file.last_modified = datetime.now().isoformat()
                    binary_file.last_analyzed = None  # 标记需要重新分析
                    break
            
            # 保存更新的项目元数据
            project_file = self.project_manager._get_project_file(self.project_name)
            project.save_to_file(str(project_file))
            
        except Exception as e:
            logger.error(f"更新二进制文件信息失败: {e}")
    
    def start(self) -> None:
        """开始监控"""
        self._update_monitored_files()
        self.file_watcher.start_monitoring()
        logger.info(f"项目 '{self.project_name}' 文件监控已启动")
    
    def stop(self) -> None:
        """停止监控"""
        self.file_watcher.stop_monitoring()
        logger.info(f"项目 '{self.project_name}' 文件监控已停止")
    
    def check_changes_now(self) -> List[FileChange]:
        """立即检查变化"""
        return self.file_watcher.check_changes()
    
    def refresh_file_list(self) -> None:
        """刷新监控的文件列表（当项目添加/删除文件时调用）"""
        self._update_monitored_files()


def create_project_monitor(project_manager, project_name: str, 
                          auto_sync: bool = False,
                          sync_callback: Optional[Callable] = None) -> ProjectFileMonitor:
    """
    便捷函数：创建项目监控器
    
    Args:
        project_manager: ProjectManager实例
        project_name: 项目名称  
        auto_sync: 是否自动同步
        sync_callback: 同步回调函数
        
    Returns:
        ProjectFileMonitor实例
    """
    return ProjectFileMonitor(
        project_manager=project_manager,
        project_name=project_name,
        auto_sync=auto_sync,
        sync_callback=sync_callback
    )


def batch_check_files(file_paths: List[str]) -> List[FileChange]:
    """
    批量检查文件变化（用于一次性检查）
    
    Args:
        file_paths: 文件路径列表
        
    Returns:
        文件变化列表
    """
    changes = []
    
    for file_path in file_paths:
        status = FileWatcher.get_file_status(file_path)
        
        if not status.exists:
            change = FileChange(
                path=file_path,
                change_type='missing',
                detected_time=datetime.now().isoformat()
            )
        else:
            change = FileChange(
                path=file_path,
                change_type='found',
                new_hash=status.hash,
                new_size=status.size,
                detected_time=datetime.now().isoformat()
            )
        
        changes.append(change)
    
    return changes