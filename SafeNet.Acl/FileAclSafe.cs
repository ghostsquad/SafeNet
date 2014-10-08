namespace SafeNet.Acl {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security.AccessControl;
    using System.Security.Principal;
    using System.Text;
    using System.Threading.Tasks;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;

    public class FileAclSafe : AclSafe<FileInfo> {
        public FileAclSafe(FileInfo fileSystemSafeObject)
            : base(fileSystemSafeObject) {
        }

        public FileAclSafe(FileInfo safeObject, IStorageSchema storageSchema)
            : base(safeObject, storageSchema) {
        }

        public FileAclSafe(FileInfo safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment)
            : base(safeObject, storageSchema, environment) {

            if (!this.environment.FileExists(safeObject.FullName)) {
                environment.WriteAllText(safeObject.FullName, string.Empty);   
            }

            this.SafeObject = safeObject;
            this.environment = environment;
            this.storageSchema = storageSchema;
        }

        public override void Protect(IEnumerable<AccessRule> rules) {
            var fileSystemSecurityObject = this.SafeObject.GetAccessControl();

            fileSystemSecurityObject.SetAccessRuleProtection(true, false);
            fileSystemSecurityObject.AddAccessRule(AclSafeConstants.GetAdminsOwnRule(isFile: true));
            fileSystemSecurityObject.SetOwner(new NTAccount(AclSafeConstants.BuiltinAdmins));
            foreach (var rule in rules) {
                fileSystemSecurityObject.SetAccessRule((FileSystemAccessRule)rule);
            }

            this.Protect(fileSystemSecurityObject);
        }

        public override void Protect(FileSystemSecurity fileSystemSecurity) {
            this.environment.SetAccessControl(this.SafeObject, fileSystemSecurity);
        }

        public override ISecret RetrieveSecret(string target) {
            throw new NotImplementedException();
        }

        public override bool StoreSecret(ISecret secret) {
            throw new NotImplementedException();
        }

        public override IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method = SafeSearchMethod.None) {
            throw new NotImplementedException();
        }

        public override IList<ISecret> SearchSecrets(string filePath, string pattern, SafeSearchMethod method = SafeSearchMethod.None) {
            throw new NotImplementedException();
        }
    }
}
