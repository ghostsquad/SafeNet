namespace SafeNet.Core {
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Security;

    public class Secret : ISecret {
        public string Target { get; set; }

        public string Username { get; set; }

        public string Password {
            get {
                if (this.SecurePassword == null) {
                    return null;
                }

                var unmanagedString = IntPtr.Zero;
                try {
                    unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(this.SecurePassword);
                    return Marshal.PtrToStringUni(unmanagedString);
                } finally {
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
                }
            }
            set {
                var securePwd = new SecureString();
                foreach (var character in value.ToCharArray()) {
                    securePwd.AppendChar(character);
                }
            }
        }

        public SecureString SecurePassword { get; set; }

        public IDictionary<string, object> Meta { get; private set; }
    }
}