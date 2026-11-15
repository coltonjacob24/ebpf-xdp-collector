package ebpf
import("context";"errors";"fmt";"net";"sync";"github.com/cilium/ebpf/link";"github.com/cilium/ebpf/ringbuf";"github.com/cilium/ebpf/rlimit")
type Loader struct{objs *xdpObjects;link link.Link;reader *ringbuf.Reader;readerClose sync.Once;closeErr error}
func NewLoader(iface string)(*Loader,error){
 if err:=rlimit.RemoveMemlock();err!=nil{return nil,fmt.Errorf("remove memlock limit: %w",err)}
 objs:=&xdpObjects{};if err:=loadXdpObjects(objs,nil);err!=nil{return nil,fmt.Errorf("load eBPF objects: %w",err)}
 networkInterface,err:=net.InterfaceByName(iface);if err!=nil{_ = objs.Close();return nil,fmt.Errorf("get interface index for %s: %w",iface,err)}
 attached,err:=link.AttachXDP(link.XDPOptions{Program:objs.XdpCollector,Interface:networkInterface.Index});if err!=nil{_ = objs.Close();return nil,fmt.Errorf("attach XDP program: %w",err)}
 reader,err:=ringbuf.NewReader(objs.Events);if err!=nil{_ = attached.Close();_ = objs.Close();return nil,fmt.Errorf("create ring buffer reader: %w",err)}
 return &Loader{objs:objs,link:attached,reader:reader},nil
}
func(l *Loader)Start(ctx context.Context,handler func([]byte))error{
 watchDone:=make(chan struct{});go func(){select{case <-ctx.Done():l.closeReader();case <-watchDone:}}();defer close(watchDone)
 for{record,err:=l.reader.Read();if err!=nil{if errors.Is(err,ringbuf.ErrClosed){return nil};return fmt.Errorf("read from ring buffer: %w",err)};handler(record.RawSample)}
}
func(l *Loader)closeReader(){l.readerClose.Do(func(){l.closeErr=l.reader.Close()})}
func(l *Loader)Close()error{l.closeReader();var errs []error;if l.closeErr!=nil{errs=append(errs,fmt.Errorf("close ring buffer reader: %w",l.closeErr))};if l.link!=nil{if err:=l.link.Close();err!=nil{errs=append(errs,fmt.Errorf("close XDP link: %w",err))}};if l.objs!=nil{if err:=l.objs.Close();err!=nil{errs=append(errs,fmt.Errorf("close eBPF objects: %w",err))}};if len(errs)>0{return fmt.Errorf("close eBPF loader: %v",errs)};return nil}
