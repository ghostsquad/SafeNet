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
        public FileAclSafe(FileInfo safeObject)
            : base(safeObject) {

            this.storageSchema.SafeFile = safeObject;
        }

        public FileAclSafe(FileInfo safeObject, IStorageSchema storageSchema)
            : base(safeObject, storageSchema) {

            this.storageSchema.SafeFile = safeObject;
        }

        public FileAclSafe(FileInfo safeObject, IStorageSchema storageSchema, EnvironmentWrapper environment)
            : base(safeObject, storageSchema, environment) {

            if (!this.environment.FileExists(safeObject.FullName)) {
                environment.WriteAllText(safeObject.FullName, string.Empty);
            }

            this.SafeObject = safeObject;
            this.environment = environment;
            this.storageSchema = storageSchema;
            this.storageSchema.SafeFile = safeObject;
        }

        public override void Protect() {
            this.Protect(new List<AccessRule>());
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

        public override ISecret RetrieveSecret(string pattern, SafeSearchMethod method) {
            return this.storageSchema.ReadSecret(pattern, method);
        }

        public override IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method) {
            throw new NotImplementedException();
        }

        public override void StoreSecret(ISecret secret) {
            this.storageSchema.WriteSecret(secret);
        }
    }
}
