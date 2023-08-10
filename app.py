from flask import Flask, render_template, request, send_file
from io import BytesIO
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
import networkx as nx
import matplotlib.pyplot as plt
import requests
from scapy.all import *
from datetime import datetime
import time 


app = Flask(__name__)

def scan_network(target_ip_range):
    #url = 'https://www.macvendorlookup.com/api/v2/'
    url = 'https://api.macvendors.com/'
    
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip_range)
    arp_responses, _ = srp(arp_request, timeout=2, verbose=False)
    
    devices = []
    graph = nx.Graph()  # Create a NetworkX graph
    
    for response in arp_responses:
        mac_address = response[1][ARP].hwsrc
        urlv1 = url + str(mac_address)
        time.sleep(2)
        responseMAC = requests.get(urlv1).text
       
        ip_address = str(response[1][ARP].psrc)
        #company_data = json.loads(responseMAC.content.decode("utf-8"))
        #company_name = company_data[0]["company"]
        
        responseICMP = sr1(IP(dst=ip_address) / ICMP(), timeout=2, verbose=False)
        
        status = "Up" if responseICMP else "Down"
        
        devices.append({
        "ip": ip_address,
        "mac": mac_address,
        "company": responseMAC,
        "status": status
    })

        graph.add_node(ip_address, label=ip_address, ip=ip_address) 

        # Add edges between nodes
        for other_response in arp_responses:
            other_ip_address = str(other_response[1][ARP].psrc)
            if ip_address != other_ip_address:
                graph.add_edge(ip_address, other_ip_address) 

    return devices, graph  

@app.route('/', methods=['GET', 'POST'])
def index():
    devices = []
    graph_image = None  

    if request.method == 'POST':
        target_ip_range = request.form['ip_range']
      
        devices, graph = scan_network(target_ip_range)
    
        graph_pos = nx.circular_layout(graph)
        center_shift = (0.6, 0.5)  # Shift the positions towards the center
        graph_pos = {node: (pos[0] * center_shift[0], pos[1] * center_shift[1]) for node, pos in graph_pos.items()}
        plt.figure(figsize=(6, 4))
        nx.draw_networkx_nodes(graph, pos=graph_pos, node_size=110)
        nx.draw_networkx_edges(graph, pos=graph_pos, edge_color='green')
        
        label_pos = {node: (pos[0], pos[1] - 0.04) for node, pos in graph_pos.items()}
        
        # Extract IP addresses from devices and use them as labels
        ip_labels = {node: data['ip'] for node, data in graph.nodes(data=True)}
        nx.draw_networkx_labels(graph, labels=ip_labels, font_size=6, font_color='black', font_family='sans-serif', pos=label_pos)

        graph_image_path = "static/graph.png"
        plt.savefig(graph_image_path)
        plt.clf()  

        graph_image = graph_image_path  

    return render_template('index.html', devices=devices, graph_image=graph_image)




if __name__ == '__main__':
    app.run(debug=True)