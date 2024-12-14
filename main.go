package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	fmt.Println("Packet Tracing Started..")

	devices, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal("Unable find the network devices")
	}

	fmt.Println("Avaliable Devices: ")

	for index, device := range devices {
		fmt.Printf("[%d] Name: %s , Description: %s\n", index, device.Name, device.Description)
		for _, address := range device.Addresses {
			fmt.Printf("Ip : %s , Netmask : %s ]\n", address.IP, address.Netmask)
		}
	}

	fmt.Println("\n Select a network device")
	var i int

	fmt.Scanln(&i)

	if i < 0 || i > len(devices) {
		log.Fatal("Invalid Device index")
	}

	selectedDeviceName := devices[i].Name

	fmt.Printf("Scanning started for device : %s \n", selectedDeviceName)

	hanlde, err := pcap.OpenLive(selectedDeviceName, 1600, true, pcap.BlockForever)

	if err != nil {
		fmt.Println(err)
		log.Fatalf("Error oprning device and Can't trace the '%s' device", selectedDeviceName)

	}

	defer hanlde.Close()

	packetSource := gopacket.NewPacketSource(hanlde, hanlde.LinkType())

	for packet := range packetSource.Packets() {
		fmt.Println("Packet captured: ")
		parsePacket(packet)
	}

}

func parsePacket(packet gopacket.Packet) {
	fmt.Println("Raw Data (byte):")
	fmt.Println(packet.Data())

	// Decode Ethernet layer
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		eth, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Printf("Ethernet:\n  SrcMAC: %s\n  DstMAC: %s\n  Type: %s\n",
			eth.SrcMAC, eth.DstMAC, eth.EthernetType)
	}

	// Decode IPv4 layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Printf("IPv4:\n  SrcIP: %s\n  DstIP: %s\n  Protocol: %s\n  TTL: %d\n",
			ip.SrcIP, ip.DstIP, ip.Protocol, ip.TTL)
	}

	// Decode TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("TCP:\n  SrcPort: %d\n  DstPort: %d\n  Seq: %d\n  Ack: %d\n",
			tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack)
	}

	// Decode UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("UDP:\n  SrcPort: %d\n  DstPort: %d\n",
			udp.SrcPort, udp.DstPort)
	}

	// Decode Application Layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		fmt.Printf("Application Layer:\n%s\n", appLayer.Payload())
	}

	// Check for decoding errors
	if errLayer := packet.ErrorLayer(); errLayer != nil {
		fmt.Printf("Error decoding packet: %v\n", errLayer.Error())
	}

	fmt.Println("----------------------------")
}
