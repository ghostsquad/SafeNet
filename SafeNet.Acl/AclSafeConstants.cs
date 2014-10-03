namespace SafeNet.Acl {
    using System.Security.AccessControl;
    using System.Security.Principal;

    public static class AclSafeConstants {
        public const string BuiltinAdmins = "BUILTIN\\Administrators";

        public static FileSystemAccessRule AdminsOwnRule {
            get {
                return new FileSystemAccessRule(
                   new NTAccount(BuiltinAdmins),
                   FileSystemRights.FullControl,
                   InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                   PropagationFlags.InheritOnly,
                   AccessControlType.Allow);
            }
        }
    }
}
