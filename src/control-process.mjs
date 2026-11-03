import {spawn} from 'node:child_process';
import {StringDecoder} from 'node:string_decoder';

// Internal control messages have bounded JSON responses. Artifact bytes use a
// separate raw pipe; neither control JSON nor binary data enter model output here.
export function runControlProcess(invocation,{input='',timeoutSeconds=20,maxOutputBytes=1600000,spawnImpl=spawn,onChild}={}) {
  return new Promise(resolve=>{
    let stdout='',stderr='',bytes=0,finished=false,timer,child,timedOut=false,truncated=false;
    const out=new StringDecoder('utf8'),err=new StringDecoder('utf8');
    const finish=(exitCode,signal,error)=>{if(finished)return;finished=true;clearTimeout(timer);if(error)stderr+=String(error).slice(0,1024);resolve({stdout,stderr,exitCode,signal,status:timedOut?'timed_out':exitCode===0?'completed':'failed',truncated});};
    try{
      child=spawnImpl(invocation.file,invocation.args,{shell:false,windowsHide:true,stdio:['pipe','pipe','pipe']});onChild?.(child);
      const capture=(stream,b)=>{bytes+=b.length;if(bytes>maxOutputBytes){truncated=true;child.kill();return;}if(stream==='stdout')stdout+=out.write(b);else stderr+=err.write(b);};
      child.stdout.on('data',b=>capture('stdout',b));child.stderr.on('data',b=>capture('stderr',b));
      child.stdout.on('end',()=>{stdout+=out.end();});child.stderr.on('end',()=>{stderr+=err.end();});
      child.once('error',e=>finish(null,null,e.message));child.once('close',(code,signal)=>finish(code,signal));child.stdin.on('error',()=>{});child.stdin.end(input);
      timer=setTimeout(()=>{timedOut=true;child.kill();},Math.max(1,timeoutSeconds)*1000);timer.unref?.();
    }catch(e){finish(null,null,e.message);}
  });
}
