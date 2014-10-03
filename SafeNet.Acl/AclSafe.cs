namespace SafeNet.Acl {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.AccessControl;
    using System.Security.Principal;

    using SafeNet.Core;

    public class AclSafe : ISafe {
        #region Constructors and Destructors

        public AclSafe(FileSystemInfo fileSystemSafeObject) {
            this.FileSystemSafeObject = fileSystemSafeObject;
            if (fileSystemSafeObject is DirectoryInfo) {
                this.FileSystemSecurityObject = new DirectorySecurity();
                if (!Directory.Exists(fileSystemSafeObject.FullName)) {
                    Directory.CreateDirectory(fileSystemSafeObject.FullName);
                }
            } else {
                this.FileSystemSecurityObject = new FileSecurity();
            }
        }

        #endregion

        #region Public Properties

        public FileSystemInfo FileSystemSafeObject { get; private set; }

        public FileSystemSecurity FileSystemSecurityObject { get; private set; }

        #endregion

        #region Public Methods and Operators

        public void Protect(IEnumerable<FileSystemAccessRule> rules, AccessRuleProtectionOptions options) {
            this.FileSystemSecurityObject.AddAccessRule(AclSafeConstants.AdminsOwnRule);
            this.FileSystemSecurityObject.SetOwner(new NTAccount(AclSafeConstants.BuiltinAdmins));
            foreach (var rule in rules) {
                this.FileSystemSecurityObject.SetAccessRule(rule);
            }

            var dirObject = this.FileSystemSafeObject as DirectoryInfo;
            if (dirObject != null) {
                dirObject.SetAccessControl(this.FileSystemSecurityObject as DirectorySecurity);
            } else {
                var fileObject = this.FileSystemSafeObject as FileInfo;
                fileObject.SetAccessControl(this.FileSystemSecurityObject as FileSecurity);
            }
        }

        public bool RetrieveSecret(string target, out ISecret secret) {
            throw new NotImplementedException();
        }

        public IList<ISecret> SearchSecrets(string pattern, SafeSearchOptions options) {
            throw new NotImplementedException();
        }

        public bool StoreSecret(ISecret secret) {
            throw new NotImplementedException();
        }

        #endregion
    }
}