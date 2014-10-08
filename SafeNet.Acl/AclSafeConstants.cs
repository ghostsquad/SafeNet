namespace SafeNet.Acl {
    using System.Security.AccessControl;
    using System.Security.Principal;

    public static class AclSafeConstants {
        public const string BuiltinAdmins = "BUILTIN\\Administrators";

        public static FileSystemAccessRule GetAdminsOwnRule(bool isFile = false) {
            FileSystemAccessRule rule = null;
            if (isFile) {
                rule = new FileSystemAccessRule(BuiltinAdmins, FileSystemRights.FullControl, AccessControlType.Allow);
            }
            else {
                rule = new FileSystemAccessRule(
                    BuiltinAdmins,
                    FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.InheritOnly,
                    AccessControlType.Allow);
            }

            return rule;
        }
    }
}
