import pandas as pd
import numpy as np
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Any
import json
from ..analyzer import PacketProcessor

class PandasAnalyzer(PacketProcessor):
    """
    Analizador que construye DataFrames de pandas para análisis avanzado
    y generación de reportes de cybersecurity.
    """
    
    def __init__(self):
        self.packet_data = []
        self.connections_data = []
        self.dns_data = []
        self.http_data = []
        self.anomalies = []
        
        # DataFrames
        self.df_packets = None
        self.df_connections = None
        self.df_dns = None
        self.df_http = None
        self.df_anomalies = None
        
        # Estadísticas
        self.stats = {
            'total_packets': 0,
            'protocol_distribution': defaultdict(int),
            'top_talkers': defaultdict(int),
            'port_scan_attempts': 0,
            'suspicious_activities': []
        }
    
    def process_packet(self, packet) -> None:
        """Procesa cada paquete y extrae datos para pandas"""
        try:
            packet_info = self._extract_packet_info(packet)
            if packet_info:
                self.packet_data.append(packet_info)
                self._check_anomalies(packet_info)
                
        except Exception as e:
            # Silenciar errores para no interrumpir el análisis
            pass
    
    def _extract_packet_info(self, packet) -> Optional[Dict]:
        """Extrae información estructurada del paquete"""
        try:
            info = {
                'timestamp': getattr(packet, 'sniff_time', datetime.now()),
                'protocol': '',
                'src_ip': '',
                'dst_ip': '',
                'src_port': '',
                'dst_port': '',
                'length': int(getattr(packet, 'length', 0)),
                'flags': '',
                'ttl': '',
                'info': ''
            }
            
            # Extraer información de capas
            for layer in packet.layers:
                layer_name = layer.layer_name
                self.stats['protocol_distribution'][layer_name] += 1
                
                if layer_name == 'ip':
                    info.update({
                        'protocol': 'IP',
                        'src_ip': getattr(layer, 'src', ''),
                        'dst_ip': getattr(layer, 'dst', ''),
                        'ttl': getattr(layer, 'ttl', '')
                    })
                
                elif layer_name == 'tcp':
                    info.update({
                        'protocol': 'TCP',
                        'src_port': getattr(layer, 'srcport', ''),
                        'dst_port': getattr(layer, 'dstport', ''),
                        'flags': getattr(layer, 'flags', '')
                    })
                    
                    # Registrar conexiones
                    if info['src_ip'] and info['dst_ip']:
                        connection_key = f"{info['src_ip']}:{info['src_port']}->{info['dst_ip']}:{info['dst_port']}"
                        self.stats['top_talkers'][info['src_ip']] += info['length']
                        
                        self.connections_data.append({
                            'connection': connection_key,
                            'src_ip': info['src_ip'],
                            'dst_ip': info['dst_ip'],
                            'src_port': info['src_port'],
                            'dst_port': info['dst_port'],
                            'protocol': 'TCP',
                            'packet_count': 1,
                            'total_bytes': info['length']
                        })
                
                elif layer_name == 'udp':
                    info.update({
                        'protocol': 'UDP',
                        'src_port': getattr(layer, 'srcport', ''),
                        'dst_port': getattr(layer, 'dstport', '')
                    })
                
                elif layer_name == 'icmp':
                    info['protocol'] = 'ICMP'
                    info['info'] = f"Type: {getattr(layer, 'type', '')}"
                
                elif layer_name == 'dns':
                    dns_info = self._extract_dns_info(layer)
                    info.update(dns_info)
                    self.dns_data.append(dns_info)
                
                elif layer_name == 'http':
                    http_info = self._extract_http_info(layer)
                    info.update(http_info)
                    self.http_data.append(http_info)
            
            return info
            
        except Exception:
            return None
    
    def _extract_dns_info(self, dns_layer) -> Dict:
        """Extrae información DNS estructurada"""
        return {
            'dns_query': getattr(dns_layer, 'qry_name', ''),
            'dns_type': getattr(dns_layer, 'qry_type', ''),
            'dns_response': getattr(dns_layer, 'resp_name', ''),
            'dns_flags': getattr(dns_layer, 'flags', '')
        }
    
    def _extract_http_info(self, http_layer) -> Dict:
        """Extrae información HTTP estructurada"""
        return {
            'http_method': getattr(http_layer, 'request_method', ''),
            'http_host': getattr(http_layer, 'host', ''),
            'http_uri': getattr(http_layer, 'request_uri', ''),
            'http_status': getattr(http_layer, 'response_code', ''),
            'http_user_agent': getattr(http_layer, 'user_agent', '')
        }
    
    def _check_anomalies(self, packet_info: Dict) -> None:
        """Detección básica de anomalías para cybersecurity"""
        anomalies = []
        
        # Detección de escaneo de puertos
        if (packet_info.get('flags') == '0x0002' and  # SYN flag
            packet_info.get('length', 0) < 100):      # Paquete pequeño
            anomalies.append('possible_port_scan')
            self.stats['port_scan_attempts'] += 1
        
        # Paquetes ICMP sospechosos
        if (packet_info.get('protocol') == 'ICMP' and 
            packet_info.get('length', 0) > 1000):     # ICMP grande
            anomalies.append('large_icmp_packet')
        
        if anomalies:
            self.anomalies.append({
                'timestamp': packet_info['timestamp'],
                'src_ip': packet_info.get('src_ip', ''),
                'dst_ip': packet_info.get('dst_ip', ''),
                'anomalies': anomalies,
                'packet_info': packet_info
            })
    
    def build_dataframes(self) -> None:
        """Construye todos los DataFrames de pandas"""
        # DataFrame de paquetes
        self.df_packets = pd.DataFrame(self.packet_data)
        if not self.df_packets.empty:
            self.df_packets['timestamp'] = pd.to_datetime(self.df_packets['timestamp'])
        
        # DataFrame de conexiones (agregado)
        if self.connections_data:
            df_conn = pd.DataFrame(self.connections_data)
            self.df_connections = df_conn.groupby([
                'connection', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'
            ]).agg({
                'packet_count': 'sum',
                'total_bytes': 'sum'
            }).reset_index()
        
        # DataFrame DNS
        if self.dns_data:
            self.df_dns = pd.DataFrame(self.dns_data)
        
        # DataFrame HTTP
        if self.http_data:
            self.df_http = pd.DataFrame(self.http_data)
        
        # DataFrame de anomalías
        if self.anomalies:
            self.df_anomalies = pd.DataFrame(self.anomalies)
    
    def generate_security_report(self) -> Dict:
        """Genera un reporte completo de seguridad"""
        if self.df_packets is None:
            self.build_dataframes()
        
        report = {
            'overview': self._get_overview_stats(),
            'top_talkers': self._get_top_talkers(),
            'protocol_analysis': self._get_protocol_analysis(),
            'anomalies_detected': self._get_anomalies_summary(),
            'dns_analysis': self._get_dns_analysis(),
            'http_analysis': self._get_http_analysis(),
            'timeline_analysis': self._get_timeline_analysis()
        }
        
        return report
    
    def _get_overview_stats(self) -> Dict:
        """Estadísticas generales del tráfico"""
        if self.df_packets.empty:
            return {}
        
        return {
            'total_packets': len(self.df_packets),
            'total_bytes': self.df_packets['length'].sum(),
            'time_duration': self.df_packets['timestamp'].max() - self.df_packets['timestamp'].min(),
            'avg_packet_size': self.df_packets['length'].mean(),
            'unique_ips': len(set(self.df_packets['src_ip'].tolist() + self.df_packets['dst_ip'].tolist()))
        }
    
    def _get_top_talkers(self) -> List[Dict]:
        """Top IPs por tráfico generado"""
        if self.df_packets.empty:
            return []
        
        top_talkers = (self.df_packets.groupby('src_ip')['length']
                      .agg(['sum', 'count'])
                      .rename(columns={'sum': 'total_bytes', 'count': 'packet_count'})
                      .sort_values('total_bytes', ascending=False)
                      .head(10))
        
        return top_talkers.reset_index().to_dict('records')
    
    def _get_protocol_analysis(self) -> Dict:
        """Análisis de distribución de protocolos"""
        if self.df_packets.empty:
            return {}
        
        protocol_stats = (self.df_packets['protocol'].value_counts()
                         .to_frame('count')
                         .assign(percentage=lambda x: (x['count'] / len(self.df_packets)) * 100))
        
        return protocol_stats.to_dict()
    
    def _get_anomalies_summary(self) -> Dict:
        """Resumen de anomalías detectadas"""
        if self.df_anomalies is None or self.df_anomalies.empty:
            return {'total_anomalies': 0, 'anomaly_types': {}}
        
        anomaly_summary = {
            'total_anomalies': len(self.df_anomalies),
            'anomaly_types': self.df_anomalies['anomalies'].explode().value_counts().to_dict(),
            'top_offenders': self.df_anomalies['src_ip'].value_counts().head(5).to_dict()
        }
        
        return anomaly_summary
    
    def _get_dns_analysis(self) -> Dict:
        """Análisis de tráfico DNS"""
        if self.df_dns is None or self.df_dns.empty:
            return {}
        
        dns_stats = {
            'total_queries': len(self.df_dns),
            'unique_domains': self.df_dns['dns_query'].nunique(),
            'top_queried_domains': self.df_dns['dns_query'].value_counts().head(10).to_dict(),
            'dns_types_distribution': self.df_dns['dns_type'].value_counts().to_dict()
        }
        
        return dns_stats
    
    def _get_http_analysis(self) -> Dict:
        """Análisis de tráfico HTTP"""
        if self.df_http is None or self.df_http.empty:
            return {}
        
        http_stats = {
            'total_requests': len(self.df_http),
            'http_methods': self.df_http['http_method'].value_counts().to_dict(),
            'top_hosts': self.df_http['http_host'].value_counts().head(10).to_dict(),
            'status_codes': self.df_http['http_status'].value_counts().to_dict(),
            'top_user_agents': self.df_http['http_user_agent'].value_counts().head(5).to_dict()
        }
        
        return http_stats
    
    def _get_timeline_analysis(self) -> Dict:
        """Análisis temporal del tráfico"""
        if self.df_packets.empty:
            return {}
        
        # Agrupar por intervalos de tiempo
        timeline = (self.df_packets.set_index('timestamp')
                   .resample('1min')['length']
                   .agg(['count', 'sum'])
                   .rename(columns={'count': 'packets_per_minute', 'sum': 'bytes_per_minute'}))
        
        return {
            'peak_traffic_time': timeline['bytes_per_minute'].idxmax().strftime('%Y-%m-%d %H:%M:%S'),
            'max_packets_per_minute': timeline['packets_per_minute'].max(),
            'max_bytes_per_minute': timeline['bytes_per_minute'].max(),
            'timeline_data': timeline.head(10).to_dict()
        }
    
    def export_to_excel(self, filename: str) -> None:
        """Exporta todos los DataFrames a un archivo Excel"""
        if any(df is None for df in [self.df_packets, self.df_connections, 
                                   self.df_dns, self.df_http, self.df_anomalies]):
            self.build_dataframes()
        
        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            if self.df_packets is not None:
                self.df_packets.to_excel(writer, sheet_name='Packets', index=False)
            
            if self.df_connections is not None:
                self.df_connections.to_excel(writer, sheet_name='Connections', index=False)
            
            if self.df_dns is not None:
                self.df_dns.to_excel(writer, sheet_name='DNS', index=False)
            
            if self.df_http is not None:
                self.df_http.to_excel(writer, sheet_name='HTTP', index=False)
            
            if self.df_anomalies is not None:
                self.df_anomalies.to_excel(writer, sheet_name='Anomalies', index=False)
            
            # Sheet de resumen
            summary_data = self.generate_security_report()
            summary_df = pd.DataFrame([summary_data['overview']])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)