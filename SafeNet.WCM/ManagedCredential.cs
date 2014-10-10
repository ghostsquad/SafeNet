using System;

namespace SafeNet.WCM {
    using System.Collections.Generic;
    using System.Security;

    using CredentialManagement;

    using SafeNet.Core;

    public class ManagedCredential : ISecret {

        private Credential credential;

        public Guid Identifier { get; set; }

        public string Target { get; set; }

        public string Username { get; set; }

        public string Password { get; set; }

        public SecureString SecurePassword { get; set; }

        public IDictionary<string, object> Meta { get; private set; }
    }
}
