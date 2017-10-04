import std.stdio;
import std.process;
import std.exception;
import std.string;
import std.algorithm;
import std.regex;
import std.range;
import std.file;
import std.path;

void main(string[] args)
{
   string clang_version;
   string dstep_dir;
   string source_dir;
   
   // Check if clang is installed
   {
      auto clang = execute(["clang", "-v"]);
      enforce(clang.status == 0, "Please install clang on your machine");
   
      auto match = clang.output.splitter("\n").front.matchFirst(regex("([3-9].[0-9].[0-9]+)"));
      enforce(match, "Can't guess clang version");
      
      clang_version = match.hit;
   }
   
   // Check if dstep is installed
   {
      // dstep need to be run from its own directory
      // where is it installed?
      auto where = executeShell("which dstep");
      enforce(where.status == 0, "Please install dstep on your machine.");
      
      // get directory
      dstep_dir = where.output[0..where.output.lastIndexOf('/')] ~ "/";
      
      // Run from its own directory, it should work.
      auto dstep = executeShell("dstep", null, Config.none, size_t.max, dstep_dir);
      enforce(dstep.status == 0, "Please install dstep on your machine. " ~ dstep.output);
   }
   

   // Try to check for mongo source 
   {
      import std.path : buildNormalizedPath;
      
      immutable current_dir = getcwd;
      
      // First try
      string mongo_c = current_dir ~ "/mongo-c-driver";
      
      // Second try
      if (!mongo_c.exists) mongo_c = current_dir ~ "/../mongo-c-driver";
      
      enforce(mongo_c.exists, "Can't find mongo-c-driver directory");
      source_dir = (mongo_c ~ "/..").buildNormalizedPath;
   }
   
   immutable dstep_include = "-I/usr/include/clang/" ~ clang_version ~ "/include";
   bool[string] seenImports;
      
   
   // Create output file
   mkdirRecurse(source_dir ~ "/source");
   auto output = File(source_dir ~ "/source/mongoc.d", "w");
   
   // 0 - Checking for versions
   output.writeln("// This file was auto-generated. Don't change it.");
   output.writeln("// mongo-c-driver version: ", readText(source_dir ~ "/mongo-c-driver/VERSION_CURRENT"));
   output.writeln("// libbson version: ", readText(source_dir ~ "/mongo-c-driver/src/libbson/VERSION_CURRENT"));
   output.writeln("extern (C): ");
   
   // 1 - Collecting libbson bindings --->
   output.writeln();
   output.writeln("// libbson stuffs --->");
  
   immutable mongoc_dir = source_dir ~ "/mongo-c-driver/src/mongoc";
   immutable bson_dir = source_dir ~ "/mongo-c-driver/src/libbson/src/bson/";
   immutable bson_include = "-I" ~ bson_dir ~ "-I"~mongoc_dir;
   
   output.writeln;
   
   // Import functions
   foreach(j; ["bson-context.h","bson.h", "bson-oid.h", "bson-string.h"])
   {
      immutable path = bson_dir ~ j;
      string command = "dstep --comments=false -DBSON_COMPILATION " ~ dstep_include ~ " " ~ bson_include ~ " " ~ path ~ " -o /tmp/tmp_binding.d";
	
      writeln("Converting ", j,  " ..."); stdout.flush;
      auto bson_conversion = executeShell(command, null, Config.none, size_t.max, dstep_dir);
      enforce(bson_conversion.status == 0, "Error running dstep. " ~ bson_conversion.output);

/*
BSON_EXPORT (const uint8_t *)
bson_get_data (const bson_t *bson);
*/

      // Check for interesting lines
      {
         import std.regex;
         auto content = readText("/tmp/tmp_binding.d");
         foreach(key; ["bson_new_from_json", "bson_as_json", "bson_strfreev", "bson_oid_init", "bson_context_get_default", "bson_context_destroy", "bson_destroy", "bson_get_data", "bson_new_from_data", "bson_init_static"])
         {
            auto m = matchAll(content, regex(";[^;]*^[^!;]*"~key~"[^;]*;", "m"));
            
            if (m)
               output.writeln(m.hit[1..$]);
         }
      }

/*
      foreach(line; File("/tmp/tmp_binding.d").byLineCopy)
      {
         foreach(key; ["bson_new_from_json (", "bson_as_json (", "bson_strfreev (", "oid_init (", "bson_context_get_default (", "bson_context_destroy (", "bson_destroy (", "bson_get_data (", "bson_new_from_data (", "bson_init_static ("])
            if (line.canFind(key))
            {
               output.writeln(line);
               break;
            }
      }
*/

   }  
   
   // bson data structs
   output.writeln("// libbson data struct --->");
   {
      string command = "dstep --comments=false -DBSON_COMPILATION " ~ dstep_include ~ " " ~ bson_include ~ " " ~ bson_dir ~ "bson-types.h" ~ " -o /tmp/tmp_binding.d";

      string[string] aliasMap;
      long parensCount;
      bool isIgnoring = false;
      
      auto bson_conversion = executeShell(command, null, Config.none, size_t.max, dstep_dir);
      enforce(bson_conversion.status == 0, "Error running dstep. " ~ bson_conversion.output);
      foreach(line; File("/tmp/tmp_binding.d").byLineCopy)
      {
         foreach(k,v; aliasMap)
            line = line.replace(k, v);
        
         if (line.startsWith("struct _bson_value_t") || line.startsWith("struct bson_iter_t")) 
         {
            output.writeln(line, ";");
            output.writeln("// IGN ", line);
            isIgnoring = true;
            continue;
         }
         
         if (isIgnoring)
         {
            parensCount+=line.count("{") - line.count("}");
            output.writeln("// IGN ", line);
            if (parensCount == 0) isIgnoring = false;
            continue;
         }
         
         if (auto first = line.matchFirst(regex("alias ([A-Za-z0-9_]+) ([A-Za-z0-9_]+);")))
         {  
            if (first[1].startsWith("_Anonymous"))
            {
               output.writeln("// found alias: ", first[1], " => ", first[2]);
               aliasMap[first[1]] = first[2];
               continue;
            }
         }
         
          
         output.writeln(line);
      }
   }
  
   
   
   // 2 - Collecting mongo bindings --->
   output.writeln();
   output.writeln("// mongo-c-clients stuffs --->");
   
   immutable mongoc_include = "-I" ~ mongoc_dir ~ " -I" ~ bson_dir;
   
   bool[string] structSignatures;
  
   // Import functions
   foreach(DirEntry j; dirEntries(mongoc_dir, SpanMode.shallow).filter!(x => x.name.endsWith(".h") &&  !x.name.endsWith("-private.h")))
   {
      // Blacklist :)
      if (["mongoc-rand.h", "utlist.h", "mongoc-version.h", "mongoc-config.h"].canFind(j.name.baseName))
         continue;

      // --- Workaround for a bug (missing declaration on mongoc-database.h)
      if (j.name.baseName == "mongoc-database.h")
      {
         auto patch = File("/tmp/mongoc-database-patched.c", "w");
         auto original = File(j, "r");
         bool patched = false;
         
         foreach(l; original.byLineCopy)
         {
            if (!patched && l.startsWith("typedef"))
            {
               patched = true;
               patch.writeln("typedef struct _mongoc_collection_t mongoc_collection_t;");
            } 
            patch.writeln(l);
         }
         
         j = DirEntry("/tmp/mongoc-database-patched.c");
      }

      // Another bug
      if (j.name.baseName =="mongoc-topology-description.h")
      {
         auto patch = File("/tmp/mongoc-topology-description-patched.c", "w");
         auto original = File(j, "r");
         bool patched = false;
         
         patch.writeln(`#include "mongoc-server-description.h"`);

         foreach(l; original.byLineCopy)
         {
            patch.writeln(l);
         }
         
         j = DirEntry("/tmp/mongoc-topology-description-patched.c");

      }

      // --- end workaround
      
      output.writeln;
      output.writeln("// from file ", j.name.baseName, ":");
      string command = "dstep -DMONGOC_I_AM_A_DRIVER -DMONGOC_COMPILATION " ~ dstep_include ~ " " ~ bson_include ~ " " ~ mongoc_include ~ " " ~ j ~ " -o /tmp/tmp_binding.d";

      writeln("Converting ", j.name.baseName, " ..."); stdout.flush;
      auto mongoc_conversion = executeShell(command, null, Config.none, size_t.max, dstep_dir);
      enforce(mongoc_conversion.status == 0, "Error running dstep. " ~ mongoc_conversion.output);
      
      if (mongoc_conversion.output.length > 0)
      {
         writeln(j, " conversion output:");
         writeln(mongoc_conversion.output);
      }
      

      // Check for interesting lines
      foreach(line; File("/tmp/tmp_binding.d").byLineCopy)
      {
         // Just written at top of generated file
         if (line.startsWith("extern")) continue;
         
         if (auto m = line.matchFirst(regex(`^(alias|struct|typedef).*;.*$`)))
         {
            import std.string : strip;
            auto stripped = line.strip();
            if (stripped in structSignatures) continue;
            else structSignatures[stripped] = true;
         }

         // I convert MONGO_XXX_YYY to YYY
         if (auto m = line.matchFirst(regex("^[ ]*enum.*(MONGOC_)[A-Z]+_.*=.*,?")))
            line = line.replace(m[1], "");


         if (auto m = line.matchFirst(regex("(MONGOC_[A-Z]+_).*=.*,?")))
            line = line.replace(m[1], "");
            
         output.writeln(line);
      }
      
   }  

   // 4 - Output generated file --->
   
   output.close;
   writeln(output.name, " written.");
}
