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
 const context = vm.createContext({ exports:{}, reactive, ref, api, ApiError, pageFromHash:()=> 'dashboard', provide:()=>{}, deskKey:0,navigateKey:1,watch:()=>{},onMounted:()=>{},onUnmounted:()=>{},setCsrf:()=>{},document:{},pages:{} })
 vm.runInContext(ts.transpileModule(script+'\nglobalThis.app={loadSetup,submitLogin,phase,loginError};',{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText,context)
 return context.app
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
