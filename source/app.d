
version(unittest)
{
   import bsond;
      
   struct MyUserStruct
   {
      this(BsonObject o) { bson = o; }
      
      @property string firstname()  { return bson["/info/firstname"].as!string; }
      @property string lastname()   { return bson["/info/lastname"].as!string; }
      @property string nickname()   { return bson["/nickname"].as!string; }
      
      @property void nickname(in string s) { bson["nickname"] = s; }
      
      BsonObject bson;
   }

   class MyUserClass
   {
      this(BsonObject o) { bson = o; }
      
      @property string firstname()  { return bson["/info/firstname"].as!string; }
      @property string lastname()   { return bson["/info/lastname"].as!string; }
      @property string nickname()   { return bson["/nickname"].as!string; }
      
      @property void nickname(in string s) { bson["nickname"] = s; }
      
      BsonObject bson;
   }
}

unittest
{
   import std.stdio;
   import std.algorithm : each;

   import std.range;
   import std.algorithm;
   import std.conv;
 
   MongoPool pool = new MongoPool("mongodb://localhost");
   Mongo mongo = pool.pop(); //new Mongo("mongodb://localhost");

   Collection c = mongo.unittest_db.unittest_collection;
   if (c.exists) c.drop();
   // Function to create a user
   BsonObject create_user(in string firstname, in string lastname, in string nickname)
   {
      return BO
      (
         "info" , BO
         (
            "firstname", firstname,
            "lastname", lastname
         ),
         "nickname", nickname
      );
   }

   
   // Try to insert
   c.insert(create_user("andrea", "fontana", "my_nick"));
   c.insert(create_user("test", "lastname", "test_user"));
   c.insert(create_user("test2", "lastname", "test2_user"));
   c.insert(create_user("test3", "lastname", "test3_user"));

   // Take one
   {
      BsonObject u = c.findOne;
      assert(c.count == 4);
      assert(u["/info/firstname"].as!string.length > 0);
      u["nickname"] = "my_new_nick";
      c.save(u);
      assert(c.count == 4);
   }

   // Take one as struct
   {
      MyUserStruct u = c.findOne!MyUserStruct;
      assert(u.firstname.length > 0);
      u.nickname = "my_new_nick";
      c.save(u);
      assert(c.count == 4);
   }

   // Take one as class
   {
      MyUserClass u = c.findOne!MyUserClass;
      assert(u.firstname.length > 0);
      u.nickname = "my_new_nick";
      c.save(u);
      assert(c.count == 4);
   }
  
   {
      assert(c.count(BO("info.lastname", "lastname")) == 3);
      assert(c.count(BO("info.lastname", "blah")) == 0);
      assert(c.count == 4);
   }
  
   {
      foreach(u; c.find())
         assert(u["/info/lastname"].as!string == "fontana" || u["/info/lastname"].as!string == "lastname");
   }

   {
      Query q = new Query;
      q.conditions = BO("info.lastname", "blah");
      assert(c.find(q).walkLength == 0);
   }
   
   {
      Query q = new Query;
      q.limit = 1;
      assert(c.find(q).walkLength == 1);
   }
   
   {
      Query q = new Query;
      q.fields = BO("nickname", true);
      
      auto u = c.findOne(q);
      
      assert(u["/info/firstname"].exists == false);
      assert(u["/info"].exists == false);
      assert(u["nickname"].exists == true);
   }
   
   {
      c.drop();
      assert(c.count == 0);
      
      auto user_range = MyUserStruct(BO("info", BO("firstname", "andrea")))
         .repeat
         .enumerate
         .stride(2)
         .take(5)
         .map!( (x) { x.value.nickname = "user_" ~ x.index.to!string; return x.value; } );

      c.insert(user_range);
      
      assert(c.count == 5);
   }

   {
      c.drop();
      assert(c.count == 0);
     
      
      auto first = BO("incremental_index", 1)
         .repeat
         .enumerate
         .take(5)
         .map!((x) { x.value["points"] = x.index.to!int; x.value["to_sum"]  = x.index % 2 == 0; return x.value; });

      auto second = BO("incremental_index", 2)
         .repeat
         .enumerate
         .drop(5)
         .take(5)
         .map!((x) { x.value["points"] = x.index.to!int; x.value["to_sum"]  = x.index % 2 == 0; return x.value; });

      c.insert(chain(first, second));
      
      {
         auto pipeline = 
            BO("pipeline", 
               BA(
                  BO("$match", BO("to_sum", true)),
                  BO("$group", BO("_id", "$incremental_index", "total", BO("$sum", "$points")))
            )
            );
            
         foreach(r; c.aggregate(pipeline))
         {
            if (r["_id"].as!int == 1) assert(r["total"].as!int == 6);
            else if (r["_id"].as!int == 2) assert(r["total"].as!int == 14);
            else assert(0);
         }
      }
      
      {
         auto pipeline = 
            BA(
               BO("$match", BO("to_sum", true)),
               BO("$group", BO("_id", "$incremental_index", "total", BO("$sum", "$points")))
            );
            
         foreach(r; c.aggregate(pipeline))
         {
            if (r["_id"].as!int == 1) assert(r["total"].as!int == 6);
            else if (r["_id"].as!int == 2) assert(r["total"].as!int == 14);
            else assert(0);
         }
      }
      
      assert(c.count == 10);
      assert(c.distinct("incremental_index") == BsonArray([1,2]));
   }

   {
      auto r = mongo.unittest_db.runCommand(BO("isMaster", 1));
      assert(r["ismaster"].as!bool == true);
   }
   
   {
      struct TestPass { const auto bson() { return BO("hello", "world"); } }
      struct TestFail { auto bson() { return BO("hello", "world"); } }
      struct TestFailToo { auto blah() { return BO("hello", "world"); }}
      
      assert(!__traits(compiles, c.save(TestFail.init)));
      assert(!__traits(compiles, c.save(TestFailToo.init)));
      assert(__traits(compiles, c.save(TestPass.init)));

      
      c.drop();
      c.save(TestPass.init);
      c.save(TestPass.init);
      c.save(TestPass.init);
      assert (c.count == 3);
      assert (c.find.all!(x => x["/hello"].as!string == "world"));
      
   }

   writeln("TESTS PASSED");
}

import mondo;
import bsond;
   
version(unittest) { void main() {} }
else void main()
{   
   // Create a connection to mongo
   Mongo mongo = new Mongo("mongodb://localhost");
   
   // Also: Collection c = mongo["my_database"]["my_collection"]
   Collection c = mongo.my_database.my_collection;
   
   // Drop collection if already exists
   if (c.exists) c.drop();
   
   // Insert a new object. BO is an alias for BsonObject
   // It inserts something like {"my_message" : "Ciao Mondo!", "my_language" : "it"}
   c.insert(BO(
      "my_message", "Ciao Mondo!",  // It actually means "Hello World!" in italian
      "my_language", "it"
   ));
   
   assert(c.count == 1); // Of course.
   
   auto obj = c.findOne(); // Returns the first object it finds
   
   // Verify it is the object we've just inserted
   assert( obj["my_message"].as!string == "Ciao Mondo!" );
   assert( obj["blah"].as!string("default") == "default"); // This field doesn't exists
   
   auto field = obj["my_message"].as!int(42); 
   assert(field == 42);             // Conversion error. Defaulted
   assert(field.exists == true);    // Field exists on db
   assert(field.ok == false);       // But can't read as int
   
   obj["my_message"]    = "Hello World!";
   obj["my_language"]   = "en";
   
   // Save back object to db
   c.save(obj);
   
   // Do a simple check for all objects inside collection (just one)
   // c.find() returns a lazy range of BsonObject.
   import std.algorithm : all;
   assert(c.find.all!(x => x["my_language"].as!string == "en") == true);
   
   bind_test();
   search_test();
}

// Class works too
struct User
{
   @property string firstname()  { return _bson["/info/firstname"].as!string; }
   @property string lastname()   { return _bson["/info/lastname"].as!string; }
   @property string nickname()   { return _bson["nickname"].as!string; }
   
   @property void nickname(in string nickname) { _bson["nickname"] = nickname; }

   // This is required if you want to read from db
   this(BsonObject bo) { _bson = bo; }
   
   // This is required if you want to save to db
   // If BsonObject obj = yourobject.bson; compiles, it's fine.
   @property auto bson() const { return _bson; }
   
   BsonObject _bson;
}
   
void bind_test()
{
   // Create a connection to mongo
   Mongo mongo = new Mongo("mongodb://localhost");
   
   // Also: Collection c = mongo["my_database"]["my_collection"]
   Collection c = mongo.my_database.my_collection;
   
   // Drop collection if already exists
   if (c.exists) c.drop();
    
   c.insert(BO("nickname", "trikko", "info", BO("firstname", "Andrea", "lastname", "Fontana")));
   c.insert(BO("nickname", "other", "info", BO("firstname", "Foo", "lastname", "Bar")));
   
   // Find return a User instead of a BsonObject
   foreach(user; c.find!User)
   {
      user.nickname = user.nickname ~ "_1";
      
      // It saves back object to db
      c.save(user);
   }
   
   import std.algorithm : all, endsWith;
   assert(c.find!User.all!(x => x.nickname.endsWith("_1")));
}

class RandomUserGenerator
{
   this() { popFront(); }
   
   void popFront() 
   {
      import std.random;
      string[] names = ["mark", "john", "andrew"];
      string name = randomSample(names, 1).front;
      
      front = BO(
         "name", name, 
         "nickname", name ~ uniform(1000,9999).to!string,
         "age", uniform(20,30),
         "points", uniform(0.0f, 100.0f)
      ); 
   }
   
   BsonObject front;
   bool empty = false;
 
}

import std.range;
import std.algorithm;
import std.array;
import std.stdio;
   
// Helper function could be a good idea
auto filterByName(Query q, in string name) { q.conditions["name"] = "mark"; return q; }
auto showFields(Query q, in string[] fields) { fields.each!(x => q.fields[x] = true); return q; }
      
void search_test()
{
   
   // Create a connection to mongo
   Mongo mongo = new Mongo("mongodb://localhost");
   
   // Also: Collection c = mongo["my_database"]["my_collection"]
   Collection c = mongo.my_database.my_collection;
   
   // Drop collection if already exists
   if (c.exists) c.drop();
   
   // Create 100 random users
   // Sort by score
   // Update ranking for the first 10 
   // Save to db the top ten
   auto data = new RandomUserGenerator()
      .take(100)
      .array
      .sort!((a,b) => a["points"].as!float < b["points"].as!float)
      .enumerate(1)
      .take(10)
      .map!( (x) { x.value["ranking"] = to!int(x.index); return x.value; } );

   // I can insert a range of custom struct/class too
   c.insert(data);
   
   // Simple query to get only nickname of users named mark
   {
      Query q = new Query();
      q.conditions["name"] = "mark";
      q.fields["nickname"] = true;
      c.find(q).each!writeln;
   }
   
   // Same query, but working with helper functions defined above
   {
      c.find
      (
         Query.init
         .filterByName("mark")
         .showFields(["nickname"])
      )
      .each!writeln;
   }
}