using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SafeNet.Core {
    using System.Text.RegularExpressions;

    public abstract class SafeBase : ISafe {
        public void UpsertSecret(ISecret secret) {
            var existing = this.RetrieveSecret(secret.Target);
            if (existing != null) {
                secret.Identifier = existing.Identifier;
            }

            this.StoreSecret(secret);
        }

        public ISecret RetrieveSecret(string target) {
            return this.SearchSecrets(target, SafeSearchMethod.None).FirstOrDefault();
        }

        public abstract void StoreSecret(ISecret secret);

        public IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method) {
            Regex regex = null;
            switch (method) {
                case SafeSearchMethod.Wildcard: {
                    regex = new Wildcard(pattern, RegexOptions.IgnoreCase);
                    break;
                }

                case SafeSearchMethod.Regex: {
                    regex = new Regex(pattern, RegexOptions.IgnoreCase);
                    break;
                }

                case SafeSearchMethod.None: {
                    break;
                }

                default: {
                    throw new NotImplementedException(string.Format("Method {0} has not been implemented.", method));
                }
            }

            IList<ISecret> secrets;
            if (regex != null) {
                secrets = this.Secrets.Where(x => regex.IsMatch(x.Target)).ToList();
            } else {
                secrets =
                    this.Secrets.Where(
                        x => string.Equals(x.Target, pattern, StringComparison.InvariantCultureIgnoreCase)).ToList();
            }

            return secrets;
        }

        public IList<ISecret> Secrets { get; private set; }
    }
}
