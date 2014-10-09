namespace SafeNet.Core {
    using System;
    using System.Collections.Generic;
    using System.Security;

    public interface ISecret {
        Guid Identifier { get; set; }

        string Target { get; set; }

        string Username { get; set; }

        string Password { get; set; }

        SecureString SecurePassword { get; set; }

        IDictionary<string, object> Meta { get; }
    }
}
