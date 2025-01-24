import sys
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit, QWidget, QFileDialog
)
from PyQt5.QtCore import QThread, pyqtSignal

class PacketCaptureThread(QThread):
    packet_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def run(self):
        try:
            sniff(prn=self.process_packet, store=False)
        except Exception as e:
            self.error_signal.emit(f"Error during packet capture: {e}")

    def process_packet(self, packet):
        output = []

        # Process Ethernet Frame
        if Ether in packet:
            eth = packet[Ether]
            output.append(f"Ethernet Frame:")
            output.append(f"\tDestination: {eth.dst}, Source: {eth.src}, Type: {hex(eth.type)}")

        # Process IPv4 Packet
        if IP in packet:
            ip = packet[IP]
            output.append(f"\tIPv4 Packet:")
            output.append(f"\t\tSource: {ip.src}, Destination: {ip.dst}, Protocol: {ip.proto}")

            # Process TCP Segment
            if TCP in packet:
                tcp = packet[TCP]
                output.append(f"\t\tTCP Segment:")
                output.append(f"\t\t\tSource Port: {tcp.sport}, Destination Port: {tcp.dport}")
                output.append(f"\t\t\tFlags: {tcp.flags}")

            # Process UDP Segment
            elif UDP in packet:
                udp = packet[UDP]
                output.append(f"\t\tUDP Segment:")
                output.append(f"\t\t\tSource Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}")

            # Process ICMP Packet
            elif ICMP in packet:
                icmp = packet[ICMP]
                output.append(f"\t\tICMP Packet:")
                output.append(f"\t\t\tType: {icmp.type}, Code: {icmp.code}")

        # Emit packet data as a signal
        self.packet_signal.emit('\n'.join(output))

class TrafficAnalyzerApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Network Traffic Analyzer")
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.start_button = QPushButton("Start Capturing")
        self.start_button.clicked.connect(self.start_capturing)
        layout.addWidget(self.start_button)

        self.save_button = QPushButton("Save Output")
        self.save_button.clicked.connect(self.save_output)
        layout.addWidget(self.save_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.packet_thread = None

    def start_capturing(self):
        self.output.append("Starting packet capture...\n")
        self.packet_thread = PacketCaptureThread()
        self.packet_thread.packet_signal.connect(self.display_packet)
        self.packet_thread.error_signal.connect(self.display_error)
        self.packet_thread.start()

    def display_packet(self, packet):
        self.output.append(packet)

    def display_error(self, error_message):
        self.output.append(f"Error: {error_message}\n")

    def save_output(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "Text Files (*.txt);;All Files (*)", options=options)
        if file_name:
            with open(file_name, 'w') as f:
                f.write(self.output.toPlainText())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TrafficAnalyzerApp()
    window.show()
    sys.exit(app.exec_())
