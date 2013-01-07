#include <stdio.h>

#include <memory>
#include <sstream>

#include <ts/ts.h>

#include <v8.h>

#define TAG_NAME "tsjs"

class JavascriptPlugin
{
	std::string m_script;
	v8::Persistent<v8::Context> m_ctxt;

	void init();

  static v8::Handle<v8::Value> getVersion(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> getInstallDir(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> getConfigDir(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> getPluginDir(v8::Local<v8::String> property, const v8::AccessorInfo& info);

  static v8::Handle<v8::Value> writeLog(const v8::Arguments& args);  
  static v8::Handle<v8::Value> reportError(const v8::Arguments& args);  

  static v8::Handle<v8::Value> registerHttpHook(const v8::Arguments& args);
public:
	JavascriptPlugin() {
		init();
	}

	bool load(const char *filename);

	bool execute(void);

	bool hook(void);
};

v8::Handle<v8::Value> JavascriptPlugin::getVersion(v8::Local<v8::String> property, const v8::AccessorInfo& info)
{
  v8::HandleScope handle_scope; 

  const char *ts_version = TSTrafficServerVersionGet();

  return handle_scope.Close(v8::String::New(ts_version));
}

v8::Handle<v8::Value> JavascriptPlugin::getInstallDir(v8::Local<v8::String> property, const v8::AccessorInfo& info)
{
  v8::HandleScope handle_scope; 

  const char *ts_version = TSInstallDirGet();

  return handle_scope.Close(v8::String::New(ts_version));
}

v8::Handle<v8::Value> JavascriptPlugin::getConfigDir(v8::Local<v8::String> property, const v8::AccessorInfo& info)
{
  v8::HandleScope handle_scope; 

  const char *ts_version = TSConfigDirGet();

  return handle_scope.Close(v8::String::New(ts_version));
}

v8::Handle<v8::Value> JavascriptPlugin::getPluginDir(v8::Local<v8::String> property, const v8::AccessorInfo& info)
{
  v8::HandleScope handle_scope; 

  const char *ts_version = TSPluginDirGet();

  return handle_scope.Close(v8::String::New(ts_version));
}

v8::Handle<v8::Value> JavascriptPlugin::writeLog(const v8::Arguments& args)
{
  if (args.Length() < 1) return v8::Undefined();

  v8::HandleScope handle_scope;
  
  v8::String::Utf8Value value(args[0]);

  TSDEBUG(TAG_NAME, *value);
  
  return v8::Undefined();
}

v8::Handle<v8::Value> JavascriptPlugin::reportError(const v8::Arguments& args)
{
  if (args.Length() < 1) return v8::Undefined();

  v8::HandleScope handle_scope;
  
  v8::String::Utf8Value value(args[0]);

  TSError(*value);
  
  return v8::Undefined();
}

v8::Handle<v8::Value> JavascriptPlugin::registerHttpHook(const v8::Arguments& args)
{
  return v8::Undefined();
}

void JavascriptPlugin::init()
{
  v8::HandleScope handle_scope;         

  v8::Handle<v8::ObjectTemplate> ats = v8::ObjectTemplate::New();

  ats->SetAccessor(v8::String::NewSymbol("version"), getVersion);
  ats->SetAccessor(v8::String::NewSymbol("installDir"), getInstallDir);
  ats->SetAccessor(v8::String::NewSymbol("configDir"), getConfigDir);
  ats->SetAccessor(v8::String::NewSymbol("pluginDir"), getPluginDir);

  ats->Set(v8::String::NewSymbol("log"), v8::FunctionTemplate::New(writeLog));
  ats->Set(v8::String::NewSymbol("error"), v8::FunctionTemplate::New(reportError));

  ats->Set(v8::String::NewSymbol("registerHttpHook"), v8::FunctionTemplate::New(registerHttpHook));

  v8::Handle<v8::ObjectTemplate> global = v8::ObjectTemplate::New();
  
  global->Set(v8::String::NewSymbol("ats"), ats);

  m_ctxt = v8::Context::New(NULL, global);
}

bool JavascriptPlugin::load(const char *filename) 
{
  TSDEBUG(TAG_NAME, "loading script from %s...\n", filename);

  TSFile fp = TSfopen(filename, "r");
  if (!fp) {
    return false;
  }

  std::ostringstream oss;
  char buf[4096];

  for (;;) {
    int err_or_len = TSfread(fp, buf, sizeof(buf));
    if (err_or_len > 0) {
      oss << std::string(buf, err_or_len);
    } else {
      break;
    }
  }

  m_script = oss.str();

  TSfclose(fp);
  
  TSDEBUG(TAG_NAME, "read %lu bytes script from %s\n", m_script.size(), filename);

  return true;
}

bool JavascriptPlugin::execute()
{
  v8::HandleScope handle_scope; 

	v8::Context::Scope context_scope(m_ctxt);

	v8::TryCatch try_catch;

	v8::Handle<v8::String> script = v8::String::New(m_script.c_str(), m_script.size());

  TSDEBUG(TAG_NAME, "compiling script...");

	v8::Handle<v8::Script> compiled_script = v8::Script::Compile(script);

	if (compiled_script.IsEmpty()) {
    v8::String::Utf8Value error(try_catch.Exception());

	  TSError("[%s] fail to compile script, %s", TAG_NAME, *error);

	  return false;
	}

  TSDEBUG(TAG_NAME, "executing script...");

	v8::Handle<v8::Value> result = compiled_script->Run();

	if (result.IsEmpty()) {
		v8::String::Utf8Value error(try_catch.Exception());

	  TSError("[%s] fail to execute script, %s", TAG_NAME, *error);

	  return false;
	}

  TSDEBUG(TAG_NAME, "execute script finished");

	return true;
}

bool JavascriptPlugin::hook() 
{
	return true;
}

int
check_ts_version()
{

  const char *ts_version = TSTrafficServerVersionGet();
  int result = 0;

  if (ts_version) {
    int major_ts_version = 0;
    int minor_ts_version = 0;
    int patch_ts_version = 0;

    if (sscanf(ts_version, "%d.%d.%d", &major_ts_version, &minor_ts_version, &patch_ts_version) != 3) {
      return 0;
    }

    /* Need at least TS 2.0 */
    if (major_ts_version >= 2) {
      result = 1;
    }

  }

  return result;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = (char *) "jsts";
  info.vendor_name = (char *) "Flier Lu";
  info.support_email = (char *) "flier.lu@gmail.com";
  
  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed.\n", TAG_NAME);
  } else if (!check_ts_version()) {
    TSError("[%s] Plugin requires Traffic Server 3.0 or later\n", TAG_NAME);
  } else if (argc != 2) {
    TSError("usage: %s <filename>\n", argv[0]);
  } else { 	
    std::auto_ptr<JavascriptPlugin> plugin(new JavascriptPlugin());

  	if (!plugin->load(argv[1])) {
  	  TSError("[%s] Could not load %s\n", TAG_NAME, argv[1]);
  	} else if (!plugin->execute()) {
  	  TSError("[%s] Could not initialize script\n", TAG_NAME);
  	} else if (!plugin->hook()) {
  	  TSError("[%s] Could not hook\n", TAG_NAME);
  	} else {
  	  TSDEBUG(TAG_NAME, "load plugin with script %s", argv[1]);

      plugin.release();

  	  return;
  	}
  }

  TSError("[%s] Unable to initialize plugin\n", TAG_NAME);
}
