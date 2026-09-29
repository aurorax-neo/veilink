import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { reactive, ref } from 'vue'
const source = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
class ApiError extends Error { constructor(message,status){super(message);this.status=status} }
function setup(api) {
 let mounted
 const context = vm.createContext({ exports:{}, reactive, ref, api, ApiError, pageFromHash:()=> 'dashboard', provide:()=>{}, deskKey:0,navigateKey:1,watch:()=>{},onMounted:fn=>{ mounted=fn },onUnmounted:()=>{},setCsrf:()=>{},setUnauthorized:()=>{},clearCsrf:()=>{},window:{addEventListener:()=>{},setInterval:()=>1},document:{visibilityState:'visible',title:''},pages:{dashboard:{title:'仪表盘'}} })
 vm.runInContext(ts.transpileModule(script+'\nglobalThis.app={loadSetup,submitLogin,phase,loginError,desk,refreshLive,resetDesk};',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText,context)
 return { ...context.app, mount:()=>mounted(), pageDocument: context.document }
}
test('first run guides registration; existing admin only login',async()=>{
 for(const required of [true,false]) {const app=setup(async()=>({registration_required:required}));await app.loadSetup();assert.equal(app.phase.value,required?'register':'login')}
})
test('setup errors and malformed response fail closed',async()=>{
 for(const api of [async()=>{throw new Error('offline')},async()=>({})]){const app=setup(api);await app.loadSetup();assert.equal(app.phase.value,'setup-error');assert.ok(app.loginError.value)}
})
test('registration succeeds into login and conflict refreshes setup',async()=>{
 let required=true
 const calls=[]
 const app=setup(async(path)=>{calls.push(path);if(path==='/setup')return {registration_required:required};return {ok:true}})
 await app.loadSetup();await app.submitLogin('admin','long password');assert.equal(app.phase.value,'login');assert.deepEqual(calls,['/setup','/register'])
 const conflict=setup(async(path)=>{if(path==='/register'){required=false;throw new ApiError('closed',409)}return {registration_required:required}})
 required=true;await conflict.loadSetup();await conflict.submitLogin('admin','long password');assert.equal(conflict.phase.value,'login')
})
test('confirmation mismatch is not submitted',()=>{
 const text=readFileSync(new URL('../src/views/LoginView.vue',import.meta.url),'utf8').match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm,'')
 let submitted=false
 const c=vm.createContext({exports:{},ref,TextEncoder,defineProps:()=>({register:true}),defineEmits:()=>()=>{submitted=true}})
 vm.runInContext(ts.transpileModule(text+'\npassword.value="long password";confirm.value="different";onSubmit();',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText,c)
 assert.equal(submitted,false)
})
test('login copy stays neutral about account identity', () => {
 const view = readFileSync(new URL('../src/views/LoginView.vue', import.meta.url), 'utf8')
 assert.match(view, /首次设置控制台登录账号/)
 assert.match(view, /<label for="username">账号<\/label>/)
 assert.match(view, /创建账号/)
 assert.doesNotMatch(view, /管理员/)
})
test('authenticated live refresh only fetches nodes, skips hidden/busy views and keeps UI quiet', async () => {
 const calls=[]
 const app=setup(async path=>{ calls.push(path); return path==='/nodes' ? [{id:'fresh',last_seen:42}] : [] })
 app.phase.value='app'
 app.desk.loaded=true
 app.desk.mappings=[{id:'existing'}]
 await app.refreshLive()
 assert.deepEqual(calls,['/nodes'])
 assert.equal(app.desk.nodes[0].last_seen,42)
 assert.equal(app.desk.mappings[0].id,'existing')
 assert.equal(app.desk.loading,false)
 assert.equal(app.desk.notice,'')
 app.pageDocument.visibilityState='hidden'
 await app.refreshLive()
 app.pageDocument.visibilityState='visible'
 app.desk.loading=true
 await app.refreshLive()
 app.desk.loading=false
 app.phase.value='login'
 await app.refreshLive()
 assert.deepEqual(calls,['/nodes'])
})

test('failed or stale live poll cannot replace state or show a success/failure notice', async () => {
 let finish
 const app=setup(()=>new Promise(resolve=>{ finish=resolve }))
 app.phase.value='app'
 const poll=app.refreshLive()
 await app.refreshLive()
 app.phase.value='login'
 app.resetDesk()
 finish([{id:'stale'}])
 await poll
 assert.equal(app.desk.nodes.length,0)
 const failed=setup(async()=>{ throw new Error('offline') })
 failed.phase.value='app'
 await failed.refreshLive()
 assert.equal(failed.desk.notice,'')
 assert.equal(failed.desk.error,'')
})

test('full reload fetches traffic independently and stale polls cannot overwrite a full refresh', async () => {
 const calls=[]
 const app=setup(async path=>{ calls.push(path); if(path==='/nodes') return [{id:'s'}]; if(path==='/mappings') return [{id:'m'}]; if(path==='/traffic') return [{mapping_id:'m',up_bytes:2,down_bytes:3,reported_at:'2026-01-01T00:00:00Z'}]; return [] })
 await app.desk.reload()
 assert.deepEqual(calls,['/nodes','/mappings','/audit','/traffic'])
 assert.equal(app.desk.loaded,true)
 assert.equal(app.desk.traffic[0].up_bytes,2)
 const unavailable=setup(async path=>{ if(path==='/traffic') throw new Error('traffic offline'); return [] })
 await unavailable.desk.reload()
 assert.equal(unavailable.desk.loaded,true)
 assert.equal(unavailable.desk.trafficLoaded,false)
 assert.match(unavailable.desk.trafficError,/流量读取失败/)
 assert.equal(unavailable.desk.notice,'')
})

test('session restoration stays on boot screen until confirmed, never flashes login', async () => {
 let release
 const calls=[]
 const active=setup(async path=>{ calls.push(path); if(path==='/setup')return {registration_required:false}; if(path==='/session')return await new Promise(resolve=>{release=resolve}); return [] })
 const restoring=active.mount()
 await new Promise(resolve=>setImmediate(resolve))
 assert.deepEqual(calls,['/setup','/session'])
 assert.equal(active.phase.value,'boot')
 release({csrf:'restored'})
 await restoring
 assert.equal(active.phase.value,'app')
 const anonymous=setup(async path=>{ if(path==='/setup')return {registration_required:false}; if(path==='/session')throw new ApiError('expired',401); return [] })
 await anonymous.mount()
 assert.equal(anonymous.phase.value,'login')
 assert.equal(anonymous.loginError.value,'')
 const firstRun=setup(async()=>({registration_required:true}))
 await firstRun.mount()
 assert.equal(firstRun.phase.value,'register')
})
