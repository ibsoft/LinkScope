using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;

namespace LinkScope {
    internal static class AiProvider {
        internal static Dictionary<string,object> Map(object x){return x as Dictionary<string,object>??new Dictionary<string,object>();}
        internal static object Get(object x,string k){object v;return Map(x).TryGetValue(k,out v)?v:null;}
        internal static object[] List(object x){var a=x as IEnumerable;return a==null||x is string||x is IDictionary?new object[0]:a.Cast<object>().ToArray();}
        internal static string Text(object x,string k){return Get(x,k) as string??"";}
        internal static object Payload(string provider,string model,string system,string prompt){
            if(provider=="bedrock")return new {system=new[]{new {text=system}},messages=new[]{new {role="user",content=new[]{new {text=prompt}}}}};
            if(provider=="anthropic")return new {model=model,max_tokens=4096,system=system,messages=new[]{new {role="user",content=prompt}}};
            if(provider=="gemini")return new {systemInstruction=new {parts=new[]{new {text=system}}},contents=new[]{new {role="user",parts=new[]{new {text=prompt}}}}};
            return new {model=model,messages=new[]{new {role="system",content=system},new {role="user",content=prompt}}};
        }
        internal static string Answer(string provider,object result){
            string answer;
            if(provider=="bedrock")answer=string.Join("\n",List(Get(Get(Get(result,"output"),"message"),"content")).Select(x=>Text(x,"text")));
            else if(provider=="cohere")answer=string.Join("\n",List(Get(Get(result,"message"),"content")).Select(x=>Text(x,"text")));
            else if(provider=="anthropic")answer=string.Join("\n",List(Get(result,"content")).Where(x=>Text(x,"type")=="text").Select(x=>Text(x,"text")));
            else if(provider=="gemini")answer=string.Join("\n",List(Get(Get(List(Get(result,"candidates")).FirstOrDefault(),"content"),"parts"))
                .Where(x=>!Equals(Get(x,"thought"),true)).Select(x=>Text(x,"text")));
            else answer=Text(Get(List(Get(result,"choices")).FirstOrDefault(),"message"),"content");
            if(string.IsNullOrWhiteSpace(answer))throw new InvalidDataException("The provider returned no answer. Check model compatibility and provider policy.");
            return answer.Length>24000?answer.Substring(0,24000)+"\n[Answer shortened]":answer.Trim();
        }
        internal static string Call(AiSettings cfg,string system,string prompt,CancellationToken cancel){
            string id=cfg.Provider,model=cfg.Profile(id).Model;
            string path=id=="bedrock"?"/model/"+Uri.EscapeDataString(model)+"/converse":id=="cohere"?"/chat":id=="anthropic"?"/messages":id=="gemini"?"/models/"+Uri.EscapeDataString(model)+":generateContent":"/chat/completions";
            var req=(HttpWebRequest)WebRequest.Create(cfg.Base(id)+path);req.Method="POST";req.ContentType="application/json";req.Accept="application/json";req.AllowAutoRedirect=false;
            req.Timeout=90000;req.ReadWriteTimeout=90000;req.UseDefaultCredentials=false;req.PreAuthenticate=false;
            string key=cfg.Key();
            if(id=="anthropic"){req.Headers["x-api-key"]=key;req.Headers["anthropic-version"]="2023-06-01";}
            else if(id=="gemini")req.Headers["x-goog-api-key"]=key;
            else if(id=="azure")req.Headers["api-key"]=key;
            else if(key.Length>0)req.Headers["Authorization"]="Bearer "+key;
            var json=Config.Json();byte[] data=Encoding.UTF8.GetBytes(json.Serialize(Payload(id,model,system,prompt)));
            using(var deadline=CancellationTokenSource.CreateLinkedTokenSource(cancel)){
                deadline.CancelAfter(90000);
                using(deadline.Token.Register(req.Abort))try{
                    req.ContentLength=data.Length;using(var stream=req.GetRequestStream())stream.Write(data,0,data.Length);
                    using(var response=(HttpWebResponse)req.GetResponse()){
                        if((int)response.StatusCode!=200)throw new InvalidDataException("The provider returned HTTP "+(int)response.StatusCode+". Verify the API base URL.");
                        using(var reader=new StreamReader(response.GetResponseStream(),Encoding.UTF8)){
                            var text=new StringBuilder();var chunk=new char[4096];int n;
                            while((n=reader.Read(chunk,0,chunk.Length))>0){if(text.Length+n>2*1024*1024)throw new InvalidDataException("The provider response exceeded 2 MiB.");text.Append(chunk,0,n);}
                            return Answer(id,json.DeserializeObject(text.ToString()));
                        }
                    }
                }catch(WebException ex){
                    if(cancel.IsCancellationRequested)throw new OperationCanceledException(cancel);
                    using(var response=ex.Response as HttpWebResponse){
                        if(response!=null)throw new InvalidDataException("Provider HTTP "+(int)response.StatusCode+". Check the API key, model access, context limit or quota.");
                    }
                    throw new InvalidDataException(deadline.IsCancellationRequested?"The provider timed out.":"Could not contact the provider ("+ex.Status+").");
                }
            }
        }
    }
}
