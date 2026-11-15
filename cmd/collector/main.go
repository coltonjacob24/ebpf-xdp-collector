package main
import("context";"errors";"fmt";"log";"os";"os/signal";"syscall";"time";"github.com/coltonjacob24/ebpf-xdp-collector/internal/config";"github.com/coltonjacob24/ebpf-xdp-collector/internal/ebpf";"github.com/coltonjacob24/ebpf-xdp-collector/internal/influx";"github.com/coltonjacob24/ebpf-xdp-collector/internal/processor")
func main(){if err:=run();err!=nil{log.Printf("collector stopped: %v",err);os.Exit(1)}}
func run()error{
 cfg,err:=config.Load("config/config.yaml");if err!=nil{return fmt.Errorf("load config: %w",err)}
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
 loader,err:=ebpf.NewLoader(cfg.Interface);if err!=nil{return fmt.Errorf("create eBPF loader: %w",err)};defer func(){if err:=loader.Close();err!=nil{log.Printf("close eBPF loader: %v",err)}}()
 writer,err:=influx.NewWriter(cfg.Influx);if err!=nil{return fmt.Errorf("create InfluxDB writer: %w",err)};defer func(){shutdownCtx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel();if err:=writer.Close(shutdownCtx);err!=nil{log.Printf("close InfluxDB writer: %v",err)}}()
 proc:=processor.New(writer);log.Printf("starting metadata collector on interface %s",cfg.Interface)
 if err:=loader.Start(ctx,proc.HandleEvent);err!=nil&&!errors.Is(err,context.Canceled){return fmt.Errorf("run collector: %w",err)}
 stats,ws:=proc.Stats(),writer.Stats();log.Printf("shutdown: events=%d parse_errors=%d write_errors=%d queued=%d queue_dropped=%d influx_dropped=%d influx_errors=%d",stats.Events,stats.ParseErrors,stats.WriteErrors,ws.Queued,ws.QueueDropped,ws.WriteDropped,ws.WriteErrors)
 return nil
}
