// --------------------------------------------------------------------------------------------------------------------
// <copyright file="Secret.cs" company="">
//   
// </copyright>
// <summary>
//   The secret.
// </summary>
// --------------------------------------------------------------------------------------------------------------------

namespace SafeNet.Core {
    using System;
    using System.Collections.Generic;
    using System.Runtime.InteropServices;
    using System.Security;

    /// <summary>
    /// The secret.
    /// </summary>
    public class Secret : ISecret {
        #region Public Properties

        /// <summary>
        /// Gets or sets the identifier.
        /// </summary>
        public Guid Identifier { get; set; }

        /// <summary>
        /// Gets the meta.
        /// </summary>
        public IDictionary<string, object> Meta { get; private set; }

        /// <summary>
        /// Gets or sets the password.
        /// </summary>
        /// <exception cref="ArgumentNullException">
        /// </exception>
        public string Password {
            get {
                if (this.SecurePassword == null) {
                    return null;
                }

                var unmanagedString = IntPtr.Zero;
                try {
                    unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(this.SecurePassword);
                    return Marshal.PtrToStringUni(unmanagedString);
                }
                finally {
                    Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
                }
            }

            set {
                if (value == null) {
                    throw new ArgumentNullException("Password cannot be null!");
                }

                this.SecurePassword = new SecureString();
                foreach (var character in value.ToCharArray()) {
                    this.SecurePassword.AppendChar(character);
                }
            }
        }

        /// <summary>
        /// Gets or sets the secure password.
        /// </summary>
        public SecureString SecurePassword { get; set; }

        /// <summary>
        /// Gets or sets the target.
        /// </summary>
        public string Target { get; set; }

        /// <summary>
        /// Gets or sets the username.
        /// </summary>
        public string Username { get; set; }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// The equals.
        /// </summary>
        /// <param name="obj">
        /// The obj.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public override bool Equals(object obj) {
            if (ReferenceEquals(null, obj)) {
                return false;
            }

            if (ReferenceEquals(this, obj)) {
                return true;
            }

            if (obj.GetType() != this.GetType()) {
                return false;
            }

            return this.Equals((ISecret)obj);
        }

        /// <summary>
        /// The get hash code.
        /// </summary>
        /// <returns>
        /// The <see cref="int"/>.
        /// </returns>
        public override int GetHashCode() {
            return this.Identifier.GetHashCode();
        }

        #endregion

        #region Methods

        /// <summary>
        /// The equals.
        /// </summary>
        /// <param name="other">
        /// The other.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        protected bool Equals(ISecret other) {
            return this.Identifier.Equals(other.Identifier);
        }

        #endregion
    }
}