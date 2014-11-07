namespace SafeNet.Acl {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.AccessControl;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;
    using SafeNet.Core.Wrappers;

    public abstract class AclSafe<T> : SafeBase
        where T : FileSystemInfo {

        protected AclSafe(T safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment) {
            this.SafeObject = safeObject;
            this.StorageSchema = storageSchema;
            this.Environment = environment;
        }

        public T SafeObject { get; protected set; }

        internal EnvironmentWrapper Environment { get; set; }

        internal IStorageSchema StorageSchema { get; set; }

        public abstract void Protect();

        public abstract void Protect(IEnumerable<AccessRule> rules);

        public abstract void Protect(FileSystemSecurity fileSystemSecurity);

        public void UpsertSecret(ISecret secret) {
            var existing = this.RetrieveSecret(secret.Target);
            if (existing != null) {
                secret.Identifier = existing.Identifier;
            }

            this.StoreSecret(secret);
        }

        public IList<ISecret> SearchSecrets(string pattern) {
            return this.SearchSecrets(pattern, SafeSearchMethod.None);
        }

        public IList<ISecret> Secrets {
            get {
                return this.StorageSchema.GetSecrets();
            }
        }
    }
}