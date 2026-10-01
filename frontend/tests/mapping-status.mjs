import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'
import { computed, reactive, ref, watch, watchEffect } from 'vue'

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const source = read('../src/views/ProxiesView.vue')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
const format = vm.createContext({ exports: {}, TextEncoder })
vm.runInContext(transpile(read('../src/format.ts')), format)
const stamp = Math.floor(Date.now()/1000)
const mapping = { id:'a', server_id:'s', client_id:'c', enabled:true }
function setup() {
 const desk=reactive({ loaded:true, loading:false, mappings:[mapping], nodes:[{id:'s',role:'server',last_seen:stamp},{id:'c',role:'client',last_seen:stamp}], traffic:[] })
 let mount,unmount
 const timers=[]
 const responses=[]
 const context=vm.createContext({exports:{},computed,reactive,ref,watch,watchEffect,...format.exports,inject:()=>desk,deskKey:{},api:()=>new Promise((resolve,reject)=>responses.push({resolve,reject})),onMounted:cb=>{mount=cb},onUnmounted:cb=>{unmount=cb},setInterval:(cb,delay)=>{timers.push({cb,delay});return timers.length},clearInterval:()=>{},registerPageRefresh:()=>()=>{}})
 vm.runInContext(transpile(script+'\nglobalThis.view={tunnelState,refreshStatus,statuses,statusError};'),context)
 return { desk,timers,responses,mount:()=>mount(),unmount:()=>unmount(),...context.view }
}
const flush=()=>new Promise(resolve=>setImmediate(resolve))
const ok={a:{server:{acknowledged:true,reason:'acknowledged',linked:true},client:{acknowledged:true,reason:'acknowledged',linked:true}}}

test('tunnel state uses live sessions, not configuration acknowledgement',async()=>{
 const e=setup()
 assert.equal(e.tunnelState(mapping).text,'未连接')
 e.mount(); assert.equal(e.timers.find(t=>t.delay===5000)?.delay,5000)
 e.responses.shift().resolve(ok); await flush()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.desk.nodes[0].error='unrelated change failed';e.desk.nodes[0].desired_revision=3;e.desk.nodes[0].applied_revision=2
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.timers.find(t=>t.delay===5000).cb()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.responses.shift().resolve({a:{server:{acknowledged:true,reason:'acknowledged',linked:false},client:{acknowledged:true,reason:'acknowledged',linked:true}}});await flush()
 assert.equal(e.tunnelState(mapping).text,'服务端未连接')
 e.unmount()
})

test('failed, malformed, stale and late responses fail closed',async()=>{
 const e=setup();e.mount()
 const stale=e.responses.shift()
 e.refreshStatus();e.responses.shift().resolve(ok);await flush()
 stale.resolve({a:{server:{acknowledged:false,reason:'unknown'},client:ok.a.client}});await flush()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.refreshStatus();e.responses.shift().reject(new Error('offline'));await flush()
 assert.equal(e.tunnelState(mapping).text,'未连接');assert.match(e.statusError.value,/失败/)
 e.refreshStatus();e.responses.shift().resolve(null);await flush()
 assert.equal(e.tunnelState(mapping).text,'未连接')
 e.refreshStatus();const late=e.responses.shift();e.unmount();late.resolve(ok);await flush()
 assert.equal(e.tunnelState(mapping).text,'未连接')
 assert.match(source,/已连接/)
 assert.doesNotMatch(source,/两端已应用|配置确认/)
})

test('desk reload clears prior status and requests fresh per-mapping acknowledgement',async()=>{
 const e=setup();e.mount()
 e.responses.shift().resolve(ok);await flush()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.desk.loading=true;await flush()
 e.desk.mappings=[{...mapping}]
 e.desk.loading=false;await flush()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 assert.ok(e.responses.length>0)
 e.responses.at(-1).resolve(ok);await flush()
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.unmount()
})

test('one side waiting stays visible beside the acknowledged side',async()=>{
 const e=setup();e.mount()
 e.responses.shift().resolve({a:{server:{acknowledged:true,reason:'acknowledged',linked:true},client:{acknowledged:false,reason:'unknown',linked:false}}});await flush()
 assert.equal(e.tunnelState(mapping).text,'客户端未连接')
 e.desk.nodes[1].last_seen=stamp-120
 assert.equal(e.tunnelState(mapping).text,'客户端离线')
 e.desk.nodes[0].last_seen=stamp-120
 assert.equal(e.tunnelState(mapping).text,'两端离线')
 e.unmount()
})
