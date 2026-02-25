import os
import time
import threading
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
import fnmatch
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler

from middleware.base import SIEMConnector
from utils.event_logger import log_event
from config.debug import DEBUG_MODE


def xml_element_to_dict(element: ET.Element) -> Dict[str, Any]:
    """
    Converte elemento XML em dict preservando hierarquia.
    
    Tratamento especial:
    - <map>: merge conteúdo no nível pai
    - <list>: converte para array
    - <ref>: preserva como dict com atributos
    """
    result = {}
    
    # Atributos do elemento (id, name, etc)
    if element.attrib:
        result.update(element.attrib)
    
    # Processar filhos
    for child in element:
        child_data = xml_element_to_dict(child)
        
        # <map> special case - merge conteúdo diretamente no pai
        if child.tag == 'map':
            if isinstance(child_data, dict):
                result.update(child_data)
        # <list> special case - array de refs ou valores
        elif child.tag == 'list':
            if isinstance(child_data, dict) and len(child_data) == 1:
                # Se list contém apenas um tipo de elemento, extrair
                result[child.tag] = list(child_data.values())[0]
            else:
                result[child.tag] = child_data if isinstance(child_data, list) else [child_data]
        # <ref> special case - preservar como dict
        elif child.tag == 'ref':
            ref_key = child.attrib.get('type', 'ref')
            if ref_key in result:
                if not isinstance(result[ref_key], list):
                    result[ref_key] = [result[ref_key]]
                result[ref_key].append(child_data)
            else:
                result[ref_key] = child_data
        # Elemento normal
        else:
            # Se já existe, converter para lista
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
    
    # Texto do elemento
    if element.text and element.text.strip():
        text_value = element.text.strip()
        if result:
            # Se já tem atributos/filhos, adicionar como _text
            result['_text'] = text_value
        else:
            # Se só tem texto, retornar direto
            return text_value
    
    return result if result else None


class ArcSightFileHandler(FileSystemEventHandler):
    """
    Handler para eventos de arquivo do watchdog.
    Processa arquivos XML do ArcSight de forma incremental.
    """
    
    def __init__(self, connector):
        self.connector = connector
        # Estado por arquivo: {path: {position: int, last_event_id: str, file_handle: file}}
        self.file_states = {}
        self.state_lock = threading.Lock()
    
    def on_created(self, event):
        """Arquivo novo criado na pasta"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        if not self._should_process_file(file_path):
            return
        
        if DEBUG_MODE:
            print(f"[DEBUG] ArcSight file created: {file_path}")
        
        # Processar arquivo do início
        self._process_file(file_path, from_start=True)
    
    def on_modified(self, event):
        """Arquivo modificado (novos eventos adicionados)"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        if not self._should_process_file(file_path):
            return
        
        if DEBUG_MODE:
            print(f"[DEBUG] ArcSight file modified: {file_path}")
        
        # Processar apenas novos eventos
        self._process_file(file_path, from_start=False)
    
    def on_deleted(self, event):
        """Arquivo deletado - limpar estado"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        if DEBUG_MODE:
            print(f"[DEBUG] ArcSight file deleted: {file_path}")
        
        with self.state_lock:
            if file_path in self.file_states:
                # Fechar handle se aberto
                if self.file_states[file_path].get('file_handle'):
                    try:
                        self.file_states[file_path]['file_handle'].close()
                    except:
                        pass
                del self.file_states[file_path]
    
    def on_moved(self, event):
        """Arquivo movido - tratar como deleted + created"""
        if event.is_directory:
            return
        
        if DEBUG_MODE:
            print(f"[DEBUG] ArcSight file moved: {event.src_path} -> {event.dest_path}")
        
        # Limpar estado do arquivo antigo
        self.on_deleted(event)
        
        # Se movido para dentro da pasta monitorada, processar
        if self._should_process_file(event.dest_path):
            # Criar mock event para dest_path
            class MockEvent:
                def __init__(self, path):
                    self.src_path = path
                    self.is_directory = False
            
            self.on_created(MockEvent(event.dest_path))
    
    def _should_process_file(self, file_path: str) -> bool:
        """Verifica se arquivo deve ser processado baseado no pattern"""
        file_pattern = self.connector.config.get("file_pattern", "*.xml")
        return fnmatch.fnmatch(os.path.basename(file_path), file_pattern)
    
    def _process_file(self, file_path: str, from_start: bool = False):
        """
        Processa arquivo XML de forma incremental.
        
        Args:
            file_path: Caminho do arquivo
            from_start: Se True, processa do início; se False, continua de onde parou
        """
        try:
            # Verificar tamanho do arquivo
            max_size_mb = self.connector.parse_options.get("max_file_size_mb", 100)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            
            if file_size_mb > max_size_mb:
                if DEBUG_MODE:
                    print(f"[WARN] File {file_path} too large ({file_size_mb:.2f}MB), skipping")
                return
            
            with self.state_lock:
                # Inicializar estado se não existe
                if file_path not in self.file_states:
                    self.file_states[file_path] = {
                        'position': 0,
                        'last_event_id': None,
                        'processed_ids': set()
                    }
                
                state = self.file_states[file_path]
                
                # Se from_start, resetar posição
                if from_start:
                    state['position'] = 0
                    state['processed_ids'].clear()
            
            # Processar XML incrementalmente
            events_processed = self._parse_xml_incremental(file_path)
            
            if DEBUG_MODE and events_processed > 0:
                print(f"[DEBUG] Processed {events_processed} SecurityEvents from {os.path.basename(file_path)}")
        
        except PermissionError:
            # Arquivo ainda sendo escrito pelo ArcSight
            if DEBUG_MODE:
                print(f"[DEBUG] File locked, will retry: {file_path}")
        
        except Exception as e:
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.connector.name,
                class_name="ArcSightFileHandler",
                method="_process_file",
                event_type="error",
                description=f"Error processing {file_path}: {str(e)}"
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to process {file_path}: {e}")
                import traceback
                traceback.print_exc()
    
    def _parse_xml_incremental(self, file_path: str) -> int:
        """
        Parse XML usando iterparse para processar incrementalmente.
        Retorna número de eventos processados.
        """
        events_processed = 0
        encoding = self.connector.parse_options.get("encoding", "UTF-8")
        
        try:
            # Usar iterparse para processar sem carregar arquivo inteiro
            context = ET.iterparse(file_path, events=('end',))
            
            for event, elem in context:
                # Processar apenas elementos SecurityEvent
                if elem.tag == 'SecurityEvent':
                    try:
                        # Verificar se já processamos este evento
                        event_id = elem.attrib.get('id')
                        
                        with self.state_lock:
                            state = self.file_states.get(file_path, {})
                            if event_id in state.get('processed_ids', set()):
                                # Já processado, skip
                                elem.clear()
                                continue
                        
                        # Converter XML para dict
                        alert = self._parse_security_event(elem)
                        
                        if alert:
                            # Validar e adicionar à fila
                            if self.connector.validate_alert(alert):
                                self.connector._add_alert(alert)
                                events_processed += 1
                                
                                # Marcar como processado
                                with self.state_lock:
                                    state = self.file_states.get(file_path, {})
                                    state['processed_ids'].add(event_id)
                                    state['last_event_id'] = event_id
                        
                        # Limpar elemento da memória
                        elem.clear()
                    
                    except Exception as e:
                        if DEBUG_MODE:
                            print(f"[ERROR] Failed to parse SecurityEvent: {e}")
                        # Continuar com próximo evento
                        elem.clear()
                        continue
                
                # Limpar elemento da memória (sem usar lxml-specific methods)
                elem.clear()
        
        except ET.ParseError as e:
            # XML incompleto ou malformado
            if DEBUG_MODE:
                print(f"[WARN] XML parse error in {file_path}: {e}")
        
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Unexpected error parsing {file_path}: {e}")
                import traceback
                traceback.print_exc()
        
        return events_processed
    
    def _parse_security_event(self, elem: ET.Element) -> Optional[Dict[str, Any]]:
        """
        Converte elemento SecurityEvent XML em dict.
        """
        try:
            # Converter elemento para dict
            alert = xml_element_to_dict(elem)
            
            if not alert:
                return None
            
            # Extrair detection_rule_id do atributo 'name'
            rule_name = alert.get('name', '')
            if rule_name:
                alert['detection_rule_id'] = rule_name
            
            # Adicionar timestamp ISO format
            start_time = alert.get('startTime', '')
            if start_time:
                try:
                    # Converter "2026-02-19 09:45:01.120" para ISO
                    dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S.%f")
                    alert['timestamp'] = dt.replace(tzinfo=timezone.utc).isoformat()
                except:
                    # Fallback para timestamp atual
                    alert['timestamp'] = datetime.now(timezone.utc).isoformat()
            else:
                alert['timestamp'] = datetime.now(timezone.utc).isoformat()
            
            # Adicionar metadata
            alert['_siem_source'] = 'arcsight'
            alert['_tenant_id'] = self.connector.tenant_id
            
            return alert
        
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to parse SecurityEvent to dict: {e}")
            return None


class ArcSightConnector(SIEMConnector):
    """
    Conector para ArcSight que monitora pasta de arquivos XML.
    """
    
    def __init__(self, name: str, config: Dict[str, Any]):
        super().__init__(name, config)
        self.directory_path = config.get("directory_path", "")
        self.file_pattern = config.get("file_pattern", "*.xml")
        self.tenant_id = config.get("tenant_id", "")
        self.tenant_config = config.get("tenant_config", {})
        self.parse_options = config.get("parse_options", {})
        self.rule_filters = config.get("rule_filters", {})
        
        self.observer = None
        self.alert_queue = []
        self.queue_lock = threading.Lock()
        
        if DEBUG_MODE:
            print(f"[DEBUG] Initializing ArcSightConnector for '{name}'")
            print(f"[DEBUG] Directory: {self.directory_path}")
            print(f"[DEBUG] Pattern: {self.file_pattern}")
            print(f"[DEBUG] Tenant: {self.tenant_id}")
    
    def connect(self) -> bool:
        """Valida que o diretório existe e tem permissão de leitura"""
        try:
            if not self.directory_path:
                if DEBUG_MODE:
                    print("[ERROR] No directory_path configured for ArcSight connector")
                return False
            
            dir_path = Path(self.directory_path)
            
            # Verificar se diretório existe
            if not dir_path.exists():
                if DEBUG_MODE:
                    print(f"[ERROR] Directory not found: {self.directory_path}")
                return False
            
            if not dir_path.is_dir():
                if DEBUG_MODE:
                    print(f"[ERROR] Path is not a directory: {self.directory_path}")
                return False
            
            # Verificar permissão de leitura
            if not os.access(self.directory_path, os.R_OK):
                if DEBUG_MODE:
                    print(f"[ERROR] No read permission for: {self.directory_path}")
                return False
            
            if DEBUG_MODE:
                print(f"[DEBUG] Successfully validated ArcSight directory")
            
            return True
        
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to connect to ArcSight directory: {e}")
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="ArcSightConnector",
                method="connect",
                event_type="error",
                description=str(e)
            )
            return False
    
    def collect_alerts(self) -> List[Dict[str, Any]]:
        """Retorna e limpa fila de alertas de forma thread-safe"""
        with self.queue_lock:
            alerts = self.alert_queue.copy()
            self.alert_queue.clear()
        return alerts
    
    def validate_alert(self, alert: Dict[str, Any]) -> bool:
        """Valida alerta aplicando filtros de regra e severidade"""
        try:
            # Verificar tenant
            tenant_id = alert.get("_tenant_id")
            if not tenant_id or tenant_id != self.tenant_id:
                return False
            
            # Aplicar filtros de regra
            rule_id = alert.get("detection_rule_id", "")
            allowed_rule_ids = self.rule_filters.get("rule_ids", ["*"])
            
            if "*" not in allowed_rule_ids:
                # Verificar se rule_id contém algum dos padrões permitidos
                if not any(allowed_rule in rule_id for allowed_rule in allowed_rule_ids):
                    if DEBUG_MODE:
                        print(f"[DEBUG] Rule filter: '{rule_id}' not in allowed rules")
                    return False
            
            # Aplicar filtro de severidade
            min_severity = self.rule_filters.get("min_severity", 0)
            if min_severity > 0:
                severity_map = {
                    "Low": 1,
                    "Medium": 2,
                    "High": 3,
                    "VeryHigh": 4
                }
                alert_severity = severity_map.get(alert.get("agentSeverity", "Low"), 1)
                
                if alert_severity < min_severity:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Severity filter: {alert_severity} < {min_severity}")
                    return False
            
            return True
        
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Error validating ArcSight alert: {e}")
            return False
    
    def start(self):
        """Inicia watchdog observer para monitorar diretório"""
        if not super().start():
            return
        
        try:
            event_handler = ArcSightFileHandler(self)
            
            # Usar PollingObserver para maior compatibilidade
            self.observer = Observer()
            self.observer.schedule(
                event_handler,
                self.directory_path,
                recursive=False
            )
            self.observer.start()
            
            if DEBUG_MODE:
                print(f"[INFO] Started watchdog observer for {self.directory_path}")
            
            # Processar arquivos existentes
            self._process_existing_files(event_handler)
        
        except Exception as e:
            log_event(
                event_id=997,
                solution_name="inopli_middleware",
                data_source=self.name,
                class_name="ArcSightConnector",
                method="start",
                event_type="error",
                description=str(e)
            )
            if DEBUG_MODE:
                print(f"[ERROR] Failed to start ArcSight observer: {e}")
    
    def stop(self):
        """Para observer e fecha recursos"""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        
        super().stop()
    
    def _add_alert(self, alert: Dict[str, Any]):
        """Adiciona alerta à fila de forma thread-safe"""
        with self.queue_lock:
            self.alert_queue.append(alert)
            # Limitar tamanho da fila
            if len(self.alert_queue) > 1000:
                self.alert_queue = self.alert_queue[-1000:]
    
    def _process_existing_files(self, handler: ArcSightFileHandler):
        """Processa arquivos XML já existentes no diretório"""
        try:
            dir_path = Path(self.directory_path)
            
            for file_path in dir_path.glob(self.file_pattern):
                if file_path.is_file():
                    if DEBUG_MODE:
                        print(f"[DEBUG] Processing existing file: {file_path}")
                    
                    handler._process_file(str(file_path), from_start=True)
        
        except Exception as e:
            if DEBUG_MODE:
                print(f"[ERROR] Failed to process existing files: {e}")
    
    def _run_loop(self):
        """
        Loop customizado para monitorar saúde do observer.
        Herda comportamento base e adiciona monitoramento.
        """
        while self.running:
            try:
                # Verificar se observer está rodando
                if self.observer and not self.observer.is_alive():
                    if DEBUG_MODE:
                        print("[WARN] Observer crashed, restarting...")
                    
                    # Reiniciar observer
                    try:
                        self.observer = Observer()
                        event_handler = ArcSightFileHandler(self)
                        self.observer.schedule(
                            event_handler,
                            self.directory_path,
                            recursive=False
                        )
                        self.observer.start()
                    except Exception as e:
                        if DEBUG_MODE:
                            print(f"[ERROR] Failed to restart observer: {e}")
                
                # Coletar e processar alertas
                alerts = self.collect_alerts()
                for alert in alerts:
                    if self.validate_alert(alert):
                        from middleware.processor import AlertProcessor
                        processor = AlertProcessor.get_instance()
                        processor.process_alert(alert, self.name)
            
            except Exception as e:
                log_event(
                    event_id=997,
                    solution_name="inopli_middleware",
                    data_source=self.name,
                    class_name="ArcSightConnector",
                    method="_run_loop",
                    event_type="error",
                    description=str(e)
                )
                if DEBUG_MODE:
                    print(f"[ERROR] Error in {self.name} connector loop: {e}")
            
            # Sleep antes de próxima verificação
            time.sleep(self.config.get("polling_interval", 5))
