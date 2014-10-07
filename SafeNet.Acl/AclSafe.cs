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

    public class AclSafe : ISafe {
        #region Constructors and Destructors

        public AclSafe(FileSystemInfo fileSystemSafeObject) : 
            this(fileSystemSafeObject, new JsonStorageSchema()) {
        }

        public AclSafe(FileSystemInfo safeObject, IStorageSchema storageSchema) : 
            this(safeObject, storageSchema, new WindowsEnvironment()) {
        }

        internal AclSafe(FileSystemInfo safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment) {
            this.SafeObject = safeObject;
            this.storageSchema = storageSchema;
            this.environment = environment;
            this.SafeObjectType = safeObject.GetType();
        }

        #endregion

        #region Public Properties

        public FileSystemInfo SafeObject { get; private set; }

        public Type SafeObjectType { get; private set; }

        private readonly IStorageSchema storageSchema;

        private readonly EnvironmentWrapper environment;

        #endregion

        #region Public Methods and Operators

        public void Protect(
            IEnumerable<AccessRule> rules,
            AccessRuleProtectionOptions options = AccessRuleProtectionOptions.Protected) {

            FileSystemSecurity fileSystemSecurityObject = null;
            if (this.SafeObjectType == typeof(FileInfo)) {
                fileSystemSecurityObject = new FileSecurity();
            } else {
                fileSystemSecurityObject = new DirectorySecurity();
            }

            fileSystemSecurityObject.AddAccessRule(AclSafeConstants.AdminsOwnRule);
            fileSystemSecurityObject.SetOwner(new NTAccount(AclSafeConstants.BuiltinAdmins));
            foreach (var rule in rules) {
                fileSystemSecurityObject.SetAccessRule(rule);
            }

            this.Protect(fileSystemSecurityObject);
        }

        public void Protect(FileSystemSecurity fileSystemSecurity) {
            this.environment.SetAccessControl(this.SafeObject, fileSystemSecurity);
        }

        public ISecret RetrieveSecret(string target) {
            throw new NotImplementedException();
        }

        public ISecret RetrieveSecret(string filePath, string target) {
            return this.SearchSecrets(filePath, target).FirstOrDefault();
        }

        public IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method = SafeSearchMethod.None) {
            throw new NotImplementedException();
        }

        public IList<ISecret> SearchSecrets(
            string filePath,
            string pattern,
            SafeSearchMethod method = SafeSearchMethod.None) {

            throw new NotImplementedException();
        }

        public bool StoreSecret(ISecret secret) {
            throw new NotImplementedException();
        }

        #endregion
    }
}