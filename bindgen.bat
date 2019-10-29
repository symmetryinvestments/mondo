d++ --preprocess-only --include-path .\mongo-c-driver\include\libbson-1.0\src --include-path .\mongo-c-driver\include\libbson-1.0 --keep-d-files source\bsonc.dpp --clang-option=-m64

d++ --preprocess-only --include-path .\mongo-c-driver\include\libmongoc-1.0 --include-path .\mongo-c-driver\include\libbson-1.0 --keep-d-files source\mongoc.dpp --clang-option=-m64
