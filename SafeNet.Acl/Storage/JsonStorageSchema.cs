namespace SafeNet.Acl.Storage {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.RegularExpressions;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using SafeNet.Core;

    public class JsonStorageSchema : IStorageSchema {
        public FileInfo SafeFile { get; set; }

        private readonly EnvironmentWrapper environment;

        public JsonStorageSchema(EnvironmentWrapper environment) : this(null, environment) {
        }

        public JsonStorageSchema(FileInfo safeFile, EnvironmentWrapper environment) {
            this.SafeFile = safeFile;
            this.environment = environment;
        }

        public ISecret ReadSecret(string searchPattern, SafeSearchMethod method) {
            if (this.SafeFile == null) {
                throw new InvalidOperationException("SafeFile has not been set.");
            }

            var jsonObject = this.GetJsonFromFile(this.SafeFile.FullName);
            ISecret secret = null;
            Regex regex = null;
            switch (method) {
                case SafeSearchMethod.Wildcard: {
                    regex = new Wildcard(searchPattern, RegexOptions.IgnoreCase);
                    break;
                }

                case SafeSearchMethod.Regex: {
                    regex = new Regex(searchPattern, RegexOptions.IgnoreCase);
                    break;
                }

                case SafeSearchMethod.None: {
                    break;
                }

                default: {
                    throw new NotImplementedException(string.Format("Method {0} has not been implemented.", method));
                }
            }

            if (secret == null){
                var secrets = GetSecretsFromJson(jsonObject);
                if (regex != null) {
                    secret = secrets.FirstOrDefault(x => regex.IsMatch(x.Target));
                } else {
                    secret =
                        secrets.FirstOrDefault(
                            x => string.Equals(x.Target, searchPattern, StringComparison.InvariantCultureIgnoreCase));
                }
            }

            return secret;
        }

        public void WriteSecret(ISecret secret) {
            if (this.SafeFile == null) {
                throw new InvalidOperationException("SafeFile has not been set.");
            }

            var secrets = this.GetSecretsListFromFile(this.SafeFile.FullName);
            var secretIndex = secrets.FindIndex(x => x.Equals(secret));
            if (secretIndex >= 0) {
                secrets.RemoveAt(secretIndex);
                secrets.Insert(secretIndex, secret);
            }
            else {
                secrets.Add(secret);
            }

            this.environment.WriteAllText(
                this.SafeFile.FullName,
                JsonConvert.SerializeObject(secrets, Formatting.Indented));
        }

        private JArray GetJsonFromFile(string path) {
            var safeContents = this.environment.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(safeContents)) {
                safeContents = "[]";
            }

            return JArray.Parse(safeContents);
        }

        private static List<ISecret> GetSecretsFromJson(JArray jsonArray) {
            return new List<ISecret>(jsonArray.ToObject<List<Secret>>());
        }

        private List<ISecret> GetSecretsListFromFile(string path) {
            var jsonArray = this.GetJsonFromFile(path);
            return GetSecretsFromJson(jsonArray);
        }
    }
}