using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using SafeNet.Core;

namespace SafeNet.Acl.Storage {
    public class JsonStorageSchema : IStorageSchema {

        public ISecret ReadSecret(FileInfo safeFile, string searchPattern, SafeSearchMethod method) {
            var jsonObject = GetJsonFromFile(safeFile.FullName);
            ISecret secret = null;
            Regex regex = null;
            switch (method) {
                case SafeSearchMethod.JsonPath: {
                    var secretJson = jsonObject.SelectToken(searchPattern);
                    secret = secretJson.ToObject<ISecret>();
                    break;
                }

                case SafeSearchMethod.Wildcard: {
                    regex = new Wildcard(searchPattern, RegexOptions.IgnoreCase);
                    break;
                }

                case SafeSearchMethod.Regex: {
                    regex = new Regex(searchPattern, RegexOptions.IgnoreCase);
                    break;
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

        public void WriteSecret(FileInfo safeFile, ISecret secret) {
            var secrets = GetSecretsListFromFile(safeFile.FullName);
            var secretIndex = secrets.FindIndex(x => x.Equals(secret));
            if (secretIndex >= 0) {
                secrets.RemoveAt(secretIndex);
                secrets.Insert(secretIndex, secret);
            }
            else {
                secrets.Add(secret);
            }

            File.WriteAllText(safeFile.FullName, JsonConvert.SerializeObject(secrets, Formatting.Indented));
        }

        private static JObject GetJsonFromFile(string path) {
            return JObject.Parse(File.ReadAllText(path));
        }

        private static List<ISecret> GetSecretsFromJson(JObject jObject) {
            return jObject.ToObject<List<ISecret>>();
        } 

        private static List<ISecret> GetSecretsListFromFile(string path) {
            var jsonObject = GetJsonFromFile(path);
            return GetSecretsFromJson(jsonObject);
        }
    }
}