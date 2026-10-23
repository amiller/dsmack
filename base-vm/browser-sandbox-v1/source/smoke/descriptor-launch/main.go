// Engineering QEMU loader: consume immutable copies of exact descriptor bytes.
package main
import("crypto/sha256";"encoding/hex";"encoding/json";"fmt";"io";"os";"os/exec";"runtime";"syscall";"unsafe")
func die(e error){fmt.Fprintln(os.Stderr,"DSMACK_DESCRIPTOR_LAUNCH_FAIL",e);os.Exit(1)}
func check(e error){if e!=nil{die(e)}}
func memfd(name string)*os.File{
 n:=append([]byte(name),0)
 fd,_,errno:=syscall.RawSyscall(319,uintptr(unsafe.Pointer(&n[0])),2,0) // linux/amd64 MFD_ALLOW_SEALING
 if errno!=0{die(errno)}
 return os.NewFile(fd,name)
}
func seal(f *os.File){_,_,e:=syscall.Syscall(syscall.SYS_FCNTL,f.Fd(),1033,15);if e!=0{die(e)}}
func fdpath(f *os.File)string{return fmt.Sprintf("/proc/self/fd/%d",f.Fd())}
func copyComponent(path string,cap int64)(*os.File,string){
 fd,e:=syscall.Open(path,syscall.O_RDONLY|syscall.O_NOFOLLOW,0);check(e);src:=os.NewFile(uintptr(fd),path);defer src.Close()
 st,e:=src.Stat();check(e);if !st.Mode().IsRegular()||st.Size()<=0||st.Size()>cap{die(fmt.Errorf("component type/size"))}
 dst:=memfd("dsmack-component");h:=sha256.New();n,e:=io.Copy(io.MultiWriter(dst,h),io.LimitReader(src,st.Size()+1));check(e)
 after,e:=src.Stat();check(e);if n!=st.Size()||after.Size()!=st.Size(){die(fmt.Errorf("component changed size"))}
 seal(dst);_,e=dst.Seek(0,0);check(e);return dst,hex.EncodeToString(h.Sum(nil))
}
func main(){
 if len(os.Args)<3||os.Args[1]!="--"{die(fmt.Errorf("expected -- qemu args"))}
 files:=map[string]*os.File{};obs:=map[string]string{"schema":"dsmack.loader-consumed/1","loader_mode":"owned-copy"}
 for _,c:=range []struct{name,key string;cap int64}{{"Image","kernel_sha256",268435456},{"initramfs.cpio.gz","initrd_sha256",268435456},{"rootfs.squashfs.verity","rootfs_sha256",2147483648},{"metadata.json","metadata_sha256",1048576}}{
  f,h:=copyComponent("/b/"+c.name,c.cap);files[c.name]=f;obs[c.key]=h
 }
 raw,e:=io.ReadAll(files["metadata.json"]);check(e);var metadata struct{Cmdline string `json:"cmdline"`};check(json.Unmarshal(raw,&metadata));if metadata.Cmdline==""{die(fmt.Errorf("missing cmdline"))};obs["cmdline"]=metadata.Cmdline
 args:=append([]string{},os.Args[2:]...)
 for i:=range args{switch args[i]{case "/b/Image":args[i]=fdpath(files["Image"]);case "/b/initramfs.cpio.gz":args[i]=fdpath(files["initramfs.cpio.gz"]);case "if=virtio,format=raw,file=/b/rootfs.squashfs.verity,readonly=on":args[i]="if=virtio,format=raw,file="+fdpath(files["rootfs.squashfs.verity"])+",readonly=on"}}
 found:=false;for i:=0;i+1<len(args);i++{if args[i]=="-append"{if found||args[i+1]!=metadata.Cmdline{die(fmt.Errorf("cmdline mismatch"))};found=true}}
 if !found{die(fmt.Errorf("missing append"))}
 encoded,e:=json.Marshal(obs);check(e);f:=memfd("dsmack-loader-observation");_,e=f.Write(encoded);check(e);seal(f)
 args=append(args,"-fw_cfg","name=opt/dsmack/loader-observation,file="+fdpath(f))
 // os.NewFile descriptors created above are inherited, not CLOEXEC.
 qemu,e:=exec.LookPath("qemu-system-aarch64");check(e);e=syscall.Exec(qemu,append([]string{qemu},args...),os.Environ());runtime.KeepAlive(files);runtime.KeepAlive(f);check(e)
}
