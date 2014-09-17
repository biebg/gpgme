//
//  main.cpp
//  gpgme
//
//  Created by yuansc on 14-8-27.
//  Copyright (c) 2014年 yuansc. All rights reserved.
//

#include <iostream>
#include <node.h>
#include <v8.h>
#include <node_buffer.h>
#include <locale.h>
#include <stdlib.h>
#include <errno.h>
#include <gpg-error.h>
#include <gpgme.h>
#include <cstring> 

using namespace v8;

using namespace node;

gpgme_ctx_t ctx;

int num = 1;
void bail(gpgme_error_t err, const char * msg){
  // run a GPG operation and throw informative errors on GPG errors
  char buff[1024];
  if(err){
    sprintf(buff, "GPG %s error: %s", msg, gpgme_strerror(err));
    printf("%s", msg);
    printf("%s",gpgme_strerror(err));
    num++;
    throw(buff);
    }
}
void str_to_data(gpgme_data_t *data, const char* string){
  bail(gpgme_data_new_from_mem(data, string, strlen(string), 1),
       "in-memory data buffer creation"); 
}

static const char *
nonnull (const char *s)
{
  return s? s :"[none]";
}

void
print_data (gpgme_data_t dh)
{
  #define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;

  ret = gpgme_data_seek (dh, 0, SEEK_SET);
  if (ret)
    bail(gpgme_err_code_from_errno (errno), "gpgmeer");
  while ((ret = gpgme_data_read (dh, buf, BUF_SIZE)) > 0)
    fwrite (buf, ret, 1, stdout);
  if (ret < 0)
    bail (gpgme_err_code_from_errno (errno), "gpgm");
}

void init_gpgme() {
	gpgme_protocol_t protocol = GPGME_PROTOCOL_OpenPGP;
gpgme_error_t err;
  gpgme_check_version (NULL);

  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifndef HAVE_W32_SYSTEM
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif
  err = gpgme_engine_check_version (protocol);
  bail(err, "engine init");
}
Handle<Value> Verify(const Arguments& args) {
	HandleScope scope;
	
  gpgme_data_t SIG, DATA;
  gpgme_verify_result_t  result;
  gpgme_signature_t sig;
 
  if (args.Length() != 3)
      return ThrowException(Exception::TypeError(
        String::New("verify takes two arguments")));

  if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("First argument must be a string (signature)")));
  String::Utf8Value signature(args[0]->ToString());

  if (!args[1]->IsString())
      return ThrowException(Exception::TypeError(
        String::New("Second argument must be a string (data)")));
    String::Utf8Value data(args[1]->ToString());

  if(!args[2]->IsFunction()) 
      return ThrowException(Exception::TypeError(
            String::New("Second argument must be a callback function")));

  Local<Function> callback = Local<Function>::Cast(args[2]);

  try{
    str_to_data(&SIG, *signature);
    str_to_data(&DATA, *data);
    bail(gpgme_op_verify(ctx, SIG, DATA, NULL), "verification");
    result = gpgme_op_verify_result(ctx);
    sig = result->signatures;
    if(sig->status == GPG_ERR_NO_ERROR) {

      const unsigned argc = 2;
      Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(String::New(sig->fpr))
      };
        // 异步回调执行 callback    
      callback->Call(Context::GetCurrent()->Global(), argc, argv);
    }
    else {
      const unsigned argc = 2;
      Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(False())
      };
      callback->Call(Context::GetCurrent()->Global(), argc, argv);
    }                               
  } catch(const char* s) {
    Local<Value> err = Exception::Error(String::New(s));
      err->ToObject()->Set(NODE_PSYMBOL("errno"), Integer::New(23));
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
   } 

   return Undefined();
}
Handle<Value> Sign(const Arguments& args) {
   HandleScope scope;
   gpgme_key_t key;
   gpgme_data_t PLAIN, SIG;
  char * sig;
  size_t amt;

    if (args.Length() != 3)
      return ThrowException(Exception::TypeError(String::New("sign takes two arguments")));

    if (!args[0]->IsString())
      return ThrowException(Exception::TypeError(String::New("First argument must be a string indicating the signer")));
    String::Utf8Value pattern(args[0]->ToString());

    if(!args[1]->IsString())
      return ThrowException(Exception::TypeError(String::New("First argument must be a string indicating the signer")));
    String::Utf8Value plain(args[1]->ToString());
    str_to_data(&PLAIN, *plain);
    if(!args[2]->IsFunction()) 
      return ThrowException(Exception::TypeError(
            String::New("Second argument must be a callback function")));

    Local<Function> callback = Local<Function>::Cast(args[2]);
  try{

    gpgme_signers_clear(ctx);
    bail(gpgme_op_keylist_start(ctx, *pattern, 1), "searching keys");
    bail(gpgme_op_keylist_next(ctx, &key), "selecting first matched key");
    bail(gpgme_op_keylist_end(ctx), "done listing keys");
    gpgme_signers_add(ctx, key);
    bail(gpgme_data_new(&SIG), "memory to hold signature");
    bail(gpgme_op_sign(ctx, PLAIN, SIG, GPGME_SIG_MODE_DETACH), "signing");

    sig = gpgme_data_release_and_get_mem(SIG, &amt);

    sig[amt] = 0;
    // return scope.Close(String::New(sig));  
  const unsigned argc = 2;
    Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(String::New(sig))
    };
    callback->Call(Context::GetCurrent()->Global(), argc, argv);


  } catch(const char* s) {
     Local<Value> err = Exception::Error(String::New(s));
      err->ToObject()->Set(NODE_PSYMBOL("errno"), Integer::New(23));
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
   } 
   return Undefined();
 }


 Handle<Value> Export(const Arguments& args) {
  HandleScope scope;
  gpgme_error_t err;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  gpgme_key_t keyarray[100];
  int keyidx = 0;
  gpgme_data_t out;

  #define BUF_SIZE 512
  char buf[BUF_SIZE + 1];
  int ret;

   if (!args[0]->IsString())
          return ThrowException(Exception::TypeError(String::New("First argument can't be empty")));
    String::Utf8Value fpr(args[0]->ToString());

    if (!args[1]->IsFunction()) {
          return ThrowException(Exception::TypeError(String::New("Second argument must be a callback function")));
    }
    Local<Function> callback = Local<Function>::Cast(args[1]);

  try {
    bail(gpgme_set_keylist_mode(ctx,4), "set mode");
    bail(gpgme_op_keylist_start (ctx, NULL,0), "op KeyList start");
    while (!(err = gpgme_op_keylist_next(ctx, &key))){
       if(strcmp(key->subkeys->fpr,*fpr)==0 || strcmp(key->subkeys->keyid,*fpr)==0) {
        keyarray[keyidx++] = key;
       }
    }
    if(keyidx==0){
      Local<Value> err = Exception::Error(String::New("Invaild fing"));
      err->ToObject()->Set(NODE_PSYMBOL("errno"), Integer::New(23));
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
    } else {

    gpgme_op_keylist_end (ctx);
    keyarray[keyidx] = NULL;
    result = gpgme_op_keylist_result (ctx);
    bail(gpgme_data_new (&out), "data_new");
    gpgme_set_armor(ctx, 1);
    // printf("%s\n out", "file");
    bail(gpgme_op_export_keys (ctx, keyarray, 4, out),"exportkeys");
    fflush (NULL);
  

    ret = gpgme_data_seek (out, 0, SEEK_SET);
    char temp[40960];
    if (ret)
      bail(gpgme_err_code_from_errno (errno), "gpgmeer");
    
    int totalSize = 0;

    while ((ret = gpgme_data_read (out, buf, BUF_SIZE)) > 0) {

      memcpy(temp + totalSize, buf, ret);

      totalSize += ret;

    }
    char result[totalSize];

    memcpy(result, temp, totalSize+1);

    const unsigned argc = 2;
    Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(String::New(result))
    };
    callback->Call(Context::GetCurrent()->Global(), argc, argv);
    if (ret < 0)
      bail (gpgme_err_code_from_errno (errno), "gpgm");
      }
  } catch(const char* s){
       Local<Value> err = Exception::Error(String::New(s));
        err->ToObject()->Set(NODE_PSYMBOL("errno"), Integer::New(00));
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
  }
  return Undefined();
 }

 Handle<Value> isSigned(const Arguments& args) {
  HandleScope scope;
  gpgme_key_t key;

 if (!args[0]->IsString())
          return ThrowException(Exception::TypeError(String::New("First argument can't be empty")));
    String::Utf8Value fpr(args[0]->ToString());

  if (!args[1]->IsFunction()) {
          return ThrowException(Exception::TypeError(String::New("Second argument must be a callback function")));
  }

  Local<Function> callback = Local<Function>::Cast(args[1]);
  

  try{
    bail(gpgme_set_keylist_mode(ctx,4), "set");
    bail(gpgme_op_keylist_start(ctx, NULL, 0), "searching keys");
   int signers=0;
   char *tempSigner[10000];
   // String signerArray[10000];
    while (!(gpgme_op_keylist_next (ctx, &key)))
    {
      gpgme_user_id_t uid;
      int nuids;
      gpgme_key_sig_t signature;
      // keyarray[keyidx++] = key;
      if(key->subkeys) {
        if(strcmp(key->subkeys->fpr, *fpr) == 0) {
          for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++)
          {
           int j=0;
           for(j=0,signature = uid->signatures; signature; signature=signature->next,j++) {
                if(signature->keyid) {
                  tempSigner[signers] = signature->keyid;
                  signers++;
            }
            }
          }
        }
      }
   }
  char *resultSigner[signers];
  memcpy(resultSigner, tempSigner, signers+1);
  Handle<v8::Array> signerArr = v8::Array::New(signers);
  for(int h=0;h<signers;h++) {
     signerArr->Set(h, v8::String::New(tempSigner[h]));
  }
  

  bail(gpgme_op_keylist_end(ctx), "done listing keys");
     const unsigned argc = 2;
    Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(signerArr)
    };
    callback->Call(Context::GetCurrent()->Global(), argc, argv);
  }catch(const char* s) {
        Local<Value> err = Exception::Error(String::New(s));
        err->ToObject()->Set(NODE_PSYMBOL("errno"), Integer::New(00));
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };
        callback->Call(Context::GetCurrent()->Global(), argc, argv);
  }
  return Undefined();
    
}



void InitAll(Handle<Object> exports) {
	 init_gpgme();
  bail(gpgme_new(&ctx), "context creation");
    gpgme_set_armor(ctx, 1);
	exports->Set(String::NewSymbol("Verify"),
		FunctionTemplate::New(Verify)->GetFunction());
  exports->Set(String::NewSymbol("Sign"),
    FunctionTemplate::New(Sign)->GetFunction());
  exports->Set(String::NewSymbol("Export"),
    FunctionTemplate::New(Export)->GetFunction());
  exports->Set(String::NewSymbol("isSigned"),
    FunctionTemplate::New(isSigned)->GetFunction());
}


NODE_MODULE(gpgme, InitAll);

