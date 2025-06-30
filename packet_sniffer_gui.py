import sys
import threading
from PyQt5 import QtWidgets, QtCore
from scapy.all import sniff, IP

class PacketSniffer(QtCore.QThread):
    packet_signal = QtCore.pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.running = True

    def run(self):
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.running)

    def process_packet(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            proto = packet[IP].proto
            packet_info = f"Source: {ip_src} | Destination: {ip_dst} | Protocol: {proto}"
            self.packet_signal.emit(packet_info)

    def stop(self):
        self.running = False

class SnifferWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 600, 400)

        self.layout = QtWidgets.QVBoxLayout()
        self.packet_display = QtWidgets.QTextEdit()
        self.packet_display.setReadOnly(True)
        self.layout.addWidget(self.packet_display)

        self.start_button = QtWidgets.QPushButton("Start Sniffing")
        self.start_button.clicked.connect(self.start_sniffing)
        self.layout.addWidget(self.start_button)

        self.stop_button = QtWidgets.QPushButton("Stop Sniffing")
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.layout.addWidget(self.stop_button)

        self.setLayout(self.layout)
        self.sniffer_thread = None

    def start_sniffing(self):
        self.sniffer_thread = PacketSniffer()
        self.sniffer_thread.packet_signal.connect(self.update_display)
        self.sniffer_thread.start()
        self.packet_display.append("Sniffing started...")

    def stop_sniffing(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.packet_display.append("Sniffing stopped.")

    def update_display(self, packet_info):
        self.packet_display.append(packet_info)

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = SnifferWindow()
    window.show()
    sys.exit(app.exec_())
