using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;

using SafeNet.Acl.Storage;
using SafeNet.Core;
using SafeNet.Core.Wrappers;

namespace SafeNet.Acl {
    public abstract class AclSafe<T> : ISafe
        where T : FileSystemInfo {
        protected AclSafe(string safePath)
            : this((T)GetFileSystemInfoObjectFromPath(safePath)) {
        }

        protected AclSafe(T safeObject)
            : this(safeObject, new JsonStorageSchema(WindowsEnvironment.Default)) {
        }

        protected AclSafe(T safeObject, IStorageSchema storageSchema)
            : this(safeObject, storageSchema, WindowsEnvironment.Default) {
        }

        protected AclSafe(T safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment) {
            this.SafeObject = safeObject;
            this.StorageSchema = storageSchema;
            this.Environment = environment;
        }

        public T SafeObject { get; protected set; }

        protected EnvironmentWrapper Environment { get; set; }

        protected IStorageSchema StorageSchema { get; set; }

        public abstract void Protect();

        public abstract void Protect(IEnumerable<AccessRule> rules);

        public abstract void Protect(FileSystemSecurity fileSystemSecurity);

        public ISecret RetrieveSecret(string target) {
            return this.RetrieveSecret(target, SafeSearchMethod.None);
        }

        public abstract ISecret RetrieveSecret(string pattern, SafeSearchMethod method);

        public IList<ISecret> SearchSecrets(string pattern) {
            return this.SearchSecrets(pattern, SafeSearchMethod.None);
        }

        public abstract IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method);

        public IList<ISecret> Secrets {
            get {
                return this.StorageSchema.GetSecrets();
            }
        }

        public abstract void StoreSecret(ISecret secret);

        private static FileSystemInfo GetFileSystemInfoObjectFromPath(string safePath) {
            var attr = File.GetAttributes(safePath);
            if (attr.HasFlag(FileAttributes.Directory) && typeof(T) == typeof(DirectoryInfo))
            {
                return new DirectoryInfo(safePath);
            }

            if (typeof(T) == typeof(FileInfo)) {
                return new FileInfo(safePath);
            }

            throw new InvalidOperationException(
                string.Format("Object at path [{0}] is expected to be {1}", safePath, typeof(T)));
        }
    }
}