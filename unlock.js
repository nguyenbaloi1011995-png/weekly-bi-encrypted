(() => {
  const originalFetch = window.fetch.bind(window);
  const scriptRoot = new URL(".", document.currentScript.src);
  const encoder = new TextEncoder();
  const roleLabels = {"all":"全部小组","group-1":"一组","group-2":"二组","group-3":"三组","group-4":"四组"};
  let unlock;
  const ready = new Promise(resolve => { unlock = resolve; });
  const urlFor = (role,name) => new URL("encrypted/"+role+"/"+name+".bin",scriptRoot);
  async function bytes(role,name) {
    const response = await originalFetch(urlFor(role,name),{cache:"no-cache"});
    if (!response.ok) throw Error("数据文件读取失败");
    return new Uint8Array(await response.arrayBuffer());
  }
  async function decrypt(role,key,name) {
    const payload = await bytes(role,name);
    return crypto.subtle.decrypt({name:"AES-GCM",iv:payload.slice(0,12),
      additionalData:encoder.encode(role+"/"+name)},key,payload.subarray(12));
  }
  window.fetch = async (input,options) => {
    const url = new URL(input instanceof Request ? input.url : input,location.href);
    const name = url.href.startsWith(scriptRoot.href) ? url.pathname.slice(scriptRoot.pathname.length) : "";
    if (!/^(data|chart-history\/data|monthly-metrics)\//.test(name)) return originalFetch(input,options);
    const {role,key} = await ready;
    const plain = new Uint8Array(await decrypt(role,key,name));
    if (/^data\//.test(name) && plain[0] === 31 && plain[1] === 139) {
      return new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("gzip")));
    }
    return new Response(plain);
  };
  const sessionName = "weekly-bi-encrypted-session-v1";
  document.addEventListener("DOMContentLoaded", async () => {
    function activate(role, key) {
      const exit = document.createElement("button");
      exit.type = "button";
      exit.textContent = "退出登录";
      exit.addEventListener("click", () => {
        sessionStorage.removeItem(sessionName);
        location.reload();
      });
      document.querySelector("nav")?.append(exit);
      unlock({role,key});
    }
    try {
      const saved = JSON.parse(sessionStorage.getItem(sessionName));
      if (saved && Object.hasOwn(roleLabels,saved.role)) {
        const key = await crypto.subtle.importKey("jwk",saved.key,"AES-GCM",false,["decrypt"]);
        await decrypt(saved.role,key,"check");
        activate(saved.role,key);
        return;
      }
    } catch {
      sessionStorage.removeItem(sessionName);
    }
    const dialog=document.createElement("dialog");
    dialog.innerHTML='<form><h1>看板登录</h1><label>访问范围<select name="role"></select></label><label>密码<input name="password" type="password" required autocomplete="current-password"></label><button>登录</button><p role="status"></p></form>';
    const form=dialog.querySelector("form");
    const status=dialog.querySelector("p");
    const button=dialog.querySelector("button");
    for(const [role,label] of Object.entries(roleLabels)) form.elements.role.add(new Option(label,role));
    dialog.addEventListener("cancel",event=>event.preventDefault());
    document.body.append(dialog);
    dialog.showModal();
    form.addEventListener("submit",async event=>{
      event.preventDefault();
      button.disabled=true;
      status.textContent="正在验证…";
      const role=form.elements.role.value;
      try {
        const material=await crypto.subtle.importKey("raw",encoder.encode(form.elements.password.value),"PBKDF2",false,["deriveKey"]);
        const key=await crypto.subtle.deriveKey({name:"PBKDF2",salt:await bytes(role,"salt"),iterations:600000,hash:"SHA-256"},
          material,{name:"AES-GCM",length:256},true,["decrypt"]);
        await decrypt(role,key,"check");
        form.reset();
        dialog.remove();
        try {
          const saved = {role,key:await crypto.subtle.exportKey("jwk",key)};
          sessionStorage.setItem(sessionName,JSON.stringify(saved));
        } catch {
          // The current page remains usable when browser storage is disabled.
        }
        activate(role,key);
      } catch {
        status.textContent="密码有误，或加密数据暂时无法读取。";
      } finally {button.disabled=false;}
    });
  });
})();
