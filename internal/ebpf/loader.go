package ebpf

import (
	"github.com/coltonjacob24/ebpf-xdp-collector/internal/ebpf"
	"log"
)

objs := &ebpf.XdpObjects{}

if err := ebpf.LoadXdpObjects(objs, nil); err != nil {
	log.Fatal(err)
}
defer objs.Close()

l, err := link.AttachXDP(link.XDPOptions{
	Program: objs.XdpCollector,
	Interface: ifindex,
})
if err != nil {
	log.Fatal(err)
}
defer l.Close()