namespace SafeNet.Core {
    using System.Collections.Generic;
    using System.Security;

    public class Secret : ISecret {
        public string Target { get; set; }

        public string Username { get; set; }

        public string Password {
            get {
                this.SecurePassword.
            }
        }

        public SecureString SecurePassword { get; set; }

        public IDictionary<string, object> Meta { get; private set; }
    }
}