using System.Linq;

using SafeNet.Acl.Storage;
using SafeNet.Core.Wrappers;

namespace SafeNet.Acl {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.AccessControl;
    using System.Security.Principal;

    using SafeNet.Core;

    public abstract class AclSafe<T> : ISafe where T : FileSystemInfo {
        #region Constructors and Destructors

        protected AclSafe(T fileSystemSafeObject) :
            this(fileSystemSafeObject, new JsonStorageSchema(WindowsEnvironment.Default)) {
        }

        protected AclSafe(T safeObject, IStorageSchema storageSchema) :
            this(safeObject, storageSchema, WindowsEnvironment.Default) {
        }

        protected AclSafe(T safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment) {
            this.SafeObject = safeObject;
            this.storageSchema = storageSchema;
            this.environment = environment;
        }

        #endregion

        #region Public Properties

        public T SafeObject { get; protected set; }

        protected IStorageSchema storageSchema;

        protected EnvironmentWrapper environment;

        #endregion

        #region Public Methods and Operators

        public abstract void Protect(IEnumerable<AccessRule> rules);

        public abstract void Protect(FileSystemSecurity fileSystemSecurity);

        public abstract ISecret RetrieveSecret(string target);

        public ISecret RetrieveSecret(string filePath, string target) {
            return this.SearchSecrets(filePath, target).FirstOrDefault();
        }

        public abstract IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method = SafeSearchMethod.None);

        public abstract IList<ISecret> SearchSecrets(
            string filePath,
            string pattern,
            SafeSearchMethod method = SafeSearchMethod.None);

        public abstract bool StoreSecret(ISecret secret);

        #endregion
    }
}