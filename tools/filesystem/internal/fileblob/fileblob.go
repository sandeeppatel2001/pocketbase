--- /tmp/codefix-worktrees-gzkngg37/worker-0/tools/filesystem/internal/fileblob/fileblob.go
+++ /tmp/codefix-worktrees-gzkngg37/worker-0/tools/filesystem/internal/fileblob/fileblob.go
@@ -476,7 +476,7 @@
 
 
 
 
 
 
 
 
 
 
 
 
 
 var md5 []byte
 var sha256hash hash.Hash
 
 // WriterOptions represents options for writing objects to Blob storage.
 type WriterOptions struct {
         // Note: any additional options fields go here.
         ContentSHA256 []byte
 
         // Pass ContentMD5 and other metadata as needed.
         Metadata map[string]string
 } 
 
 wopts := blob.WriterOptions{
+       ContentSHA256: xa.ContentSHA256,
 
 // Replace md5.New() with sha256.New()
   w.md5hash = sha256.New() 
 
 