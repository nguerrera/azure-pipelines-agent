// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using Xunit;

namespace Microsoft.VisualStudio.Services.Agent.Tests
{
    public sealed class HostContextL0
    {
        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        public void CreateServiceReturnsNewInstance()
        {
            // Arrange.
            using (var _hc = Setup())
            {
                // Act.
                var reference1 = _hc.CreateService<IAgentServer>();
                var reference2 = _hc.CreateService<IAgentServer>();

                // Assert.
                Assert.NotNull(reference1);
                Assert.IsType<AgentServer>(reference1);
                Assert.NotNull(reference2);
                Assert.IsType<AgentServer>(reference2);
                Assert.False(object.ReferenceEquals(reference1, reference2));
            }
        }

        [Fact]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        public void GetServiceReturnsSingleton()
        {
            // Arrange.
            using (var _hc = Setup())
            {

                // Act.
                var reference1 = _hc.GetService<IAgentServer>();
                var reference2 = _hc.GetService<IAgentServer>();

                // Assert.
                Assert.NotNull(reference1);
                Assert.IsType<AgentServer>(reference1);
                Assert.NotNull(reference2);
                Assert.True(object.ReferenceEquals(reference1, reference2));
            }
        }

        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // some URLs with secrets to mask
        [InlineData("https://user:pass@example.com/path", "https://user:***@example.com/path")]
        [InlineData("http://user:pass@example.com/path", "http://user:***@example.com/path")]
        [InlineData("ftp://user:pass@example.com/path", "ftp://user:***@example.com/path")]
        [InlineData("https://user:pass@example.com/weird:thing@path", "https://user:***@example.com/weird:thing@path")]
        [InlineData("https://user:pass@example.com:8080/path", "https://user:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2@example.com:8080/path")]
        // some URLs without secrets to mask
        [InlineData("https://example.com/path", "https://example.com/path")]
        [InlineData("http://example.com/path", "http://example.com/path")]
        [InlineData("ftp://example.com/path", "ftp://example.com/path")]
        [InlineData("ssh://example.com/path", "ssh://example.com/path")]
        [InlineData("https://example.com/@path", "https://example.com/@path")]
        [InlineData("https://example.com/weird:thing@path", "https://example.com/weird:thing@path")]
        [InlineData("https://example.com:8080/path", "https://example.com:8080/path")]
        public void UrlSecretsAreMaskedOssSecretMasker(string input, string expected)
        {
            // Arrange.

            try
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", "true");
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);

                using (var _hc = Setup())
                {
                    // Act.
                    var result = _hc.SecretMasker.MaskSecrets(input);

                    // Assert.
                    Assert.Equal(expected, result);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", "true");
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);
            }
        }

        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // some URLs with secrets to mask
        [InlineData("https://user:pass@example.com/path", "https://user:***@example.com/path")]
        [InlineData("http://user:pass@example.com/path", "http://user:***@example.com/path")]
        [InlineData("ftp://user:pass@example.com/path", "ftp://user:***@example.com/path")]
        [InlineData("https://user:pass@example.com/weird:thing@path", "https://user:***@example.com/weird:thing@path")]
        [InlineData("https://user:pass@example.com:8080/path", "https://user:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2@example.com:8080/path")]
        // some URLs without secrets to mask
        [InlineData("https://example.com/path", "https://example.com/path")]
        [InlineData("http://example.com/path", "http://example.com/path")]
        [InlineData("ftp://example.com/path", "ftp://example.com/path")]
        [InlineData("ssh://example.com/path", "ssh://example.com/path")]
        [InlineData("https://example.com/@path", "https://example.com/@path")]
        [InlineData("https://example.com/weird:thing@path", "https://example.com/weird:thing@path")]
        [InlineData("https://example.com:8080/path", "https://example.com:8080/path")]
        public void UrlSecretsAreMaskedBuiltInSecretMasker(string input, string expected)
        {
            // Arrange.

            try
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", null);
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", "true");

                using (var _hc = Setup())
                {
                    // Act.
                    var result = _hc.SecretMasker.MaskSecrets(input);

                    // Assert.
                    Assert.Equal(expected, result);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", null);
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);
            }
        }

        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // some URLs with secrets to mask
        [InlineData("https://user:pass@example.com/path", "https://user:***@example.com/path")]
        [InlineData("http://user:pass@example.com/path", "http://user:***@example.com/path")]
        [InlineData("ftp://user:pass@example.com/path", "ftp://user:***@example.com/path")]
        [InlineData("https://user:pass@example.com/weird:thing@path", "https://user:***@example.com/weird:thing@path")]
        [InlineData("https://user:pass@example.com:8080/path", "https://user:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user@example.com:8080/path\nhttps://user2:pass2@example.com:8080/path", "https://user@example.com:8080/path\nhttps://user2:***@example.com:8080/path")]
        [InlineData("https://user:pass@example.com:8080/path\nhttps://user2@example.com:8080/path", "https://user:***@example.com:8080/path\nhttps://user2@example.com:8080/path")]
        // some URLs without secrets to mask
        [InlineData("https://example.com/path", "https://example.com/path")]
        [InlineData("http://example.com/path", "http://example.com/path")]
        [InlineData("ftp://example.com/path", "ftp://example.com/path")]
        [InlineData("ssh://example.com/path", "ssh://example.com/path")]
        [InlineData("https://example.com/@path", "https://example.com/@path")]
        [InlineData("https://example.com/weird:thing@path", "https://example.com/weird:thing@path")]
        [InlineData("https://example.com:8080/path", "https://example.com:8080/path")]
        public void UrlSecretsAreMaskedSecretMaskerVSO(string input, string expected)
        {
            // Arrange.

            Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", null);
            Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);

            using (var _hc = Setup())
            {
                // Act.
                var result = _hc.SecretMasker.MaskSecrets(input);

                // Assert.
                Assert.Equal(expected, result);
            }
        }

        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // Some secrets that the scanner SHOULD suppress.
        // NOTE: String concat used to highlight signatures and avoid false positives from push protection.
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "APIM" + "do9bzQ==", "SEC101/181:AQYnVRHEp9bsvtiS75Hw")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "ACDb" + "OpqrYA==", "SEC101/160:cgAuNarRt3XE67OyFKtT")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ABa" + "cEmI0Q==", "SEC101/163:hV8JHmDwlzKVQLDQ4aVz")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+AMC" + "IBB+lg==", "SEC101/170:vGkdeeXzDdYpZG/P/N+U")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ASt" + "aCQW6A==", "SEC101/152:iFwwHb6GCjF+WxbWkhIp")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead" + "AzFu" + "FakD8w==", "SEC101/158:DI3pIolg4mUyaYvnQJ9s")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeadxx" + "AzSe" + "CyiycA", "SEC101/166:ws3fLn9rYjxet8tPxeei")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ACR" + "C5W7f3", "SEC101/176:gfxbCiSbZlGd1NSqkoQg")]
        [InlineData("oy2" + "mdeaddeaddeadeadqdeaddeadxxxezodeaddeadwxuq", "SEC101/031:G47Z8IeLmqos+/TXkWoH")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AIoT" + "Oumzco=", "SEC101/178:oCE/hp1BfeSLXPJgMqTz")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ASb" + "HpHeAI=", "SEC101/171:ujJlDjBUPI6u49AyMCXk")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+AEh" + "G2s/8w=", "SEC101/172:7aH00tlYEZcu0yhnxhm6")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ARm" + "D7h+qo=", "SEC101/173:73UIu7xCGv6ofelm1yqH")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AzCa" + "JM04l8=", "SEC101/154:Elbi036ZI8k03jlXzG52")]
        [InlineData("xxx" + "8Q~" + "dead.dead.DEAD-DEAD-dead~deadxxxxx", "SEC101/156:vcocI2kI5E2ycoG55kza")]
        [InlineData("npm_" + "deaddeaddeaddeaddeaddeaddeaddeaddead", "SEC101/050:bUOMn/+Dx0jUK71D+nHu")]
        [InlineData("xxx" + "7Q~" + "dead.dead.DEAD-DEAD-dead~deadxx", "SEC101/156:WNRIG2TMMQjdUEGSNRIQ")]
        // Some secrets that the scanner should NOT suppress.
        [InlineData("SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==", "SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==")]
        [InlineData("The password is knock knock knock", "The password is knock knock knock")]
        public void OtherSecretsAreMaskedOssSecretsMasker(string input, string expected)
        {
            // Arrange.
            try
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", "true");
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);

                using (var _hc = Setup(testName: nameof(OtherSecretsAreMaskedOssSecretsMasker)))
                {
                    // Act.
                    var result = _hc.SecretMasker.MaskSecrets(input);

                    // Assert.
                    Assert.Equal(expected, result);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", "true");
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);
            }
        }
        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // Some secrets that the scanner SHOULD suppress.
        // NOTE: String concat used to highlight signatures and avoid false positives from push protection.
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "APIM" + "do9bzQ==", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "ACDb" + "OpqrYA==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ABa" + "cEmI0Q==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+AMC" + "IBB+lg==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ASt" + "aCQW6A==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead" + "AzFu" + "FakD8w==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeadxx" + "AzSe" + "CyiycA", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ACR" + "C5W7f3", "***")]
        [InlineData("oy2" + "mdeaddeaddeadeadqdeaddeadxxxezodeaddeadwxuq", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AIoT" + "Oumzco=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ASb" + "HpHeAI=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+AEh" + "G2s/8w=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ARm" + "D7h+qo=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AzCa" + "JM04l8=", "***")]
        [InlineData("xxx" + "8Q~" + "dead.dead.DEAD-DEAD-dead~deadxxxxx", "***")]
        [InlineData("npm_" + "deaddeaddeaddeaddeaddeaddeaddeaddead", "***")]
        [InlineData("xxx" + "7Q~" + "dead.dead.DEAD-DEAD-dead~deadxx", "***")]
        // Some secrets that the scanner should NOT suppress.
        [InlineData("SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==", "SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==")]
        [InlineData("The password is knock knock knock", "The password is knock knock knock")]
        public void OtherSecretsAreMaskedBuiltInSecretsMasker(string input, string expected)
        {
            // Arrange.
            try
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", null);
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", "true");

                using (var _hc = Setup())
                {
                    // Act.
                    var result = _hc.SecretMasker.MaskSecrets(input);

                    // Assert.
                    Assert.Equal(expected, result);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", "true");
                Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);
            }
        }

        [Theory]
        [Trait("Level", "L0")]
        [Trait("Category", "Common")]
        // Some secrets that the scanner SHOULD suppress.
        // NOTE: String concat used to highlight signatures and avoid false positives from push protection.
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "APIM" + "do9bzQ==", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "ACDb" + "OpqrYA==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ABa" + "cEmI0Q==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+AMC" + "IBB+lg==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead" + "+ASt" + "aCQW6A==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead" + "AzFu" + "FakD8w==", "***")]
        [InlineData("deaddeaddeaddeaddeaddeaddeaddeaddeaddeadxx" + "AzSe" + "CyiycA", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ACR" + "C5W7f3", "***")]
        [InlineData("oy2" + "mdeaddeaddeadeadqdeaddeadxxxezodeaddeadwxuq", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AIoT" + "Oumzco=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ASb" + "HpHeAI=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+AEh" + "G2s/8w=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "+ARm" + "D7h+qo=", "***")]
        [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + "AzCa" + "JM04l8=", "***")]
        [InlineData("xxx" + "8Q~" + "dead.dead.DEAD-DEAD-dead~deadxxxxx", "***")]
        [InlineData("npm_" + "deaddeaddeaddeaddeaddeaddeaddeaddead", "***")]
        [InlineData("xxx" + "7Q~" + "dead.dead.DEAD-DEAD-dead~deadxx", "***")]
        // Some secrets that the scanner should NOT suppress.
        [InlineData("SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==", "SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==")]
        [InlineData("The password is knock knock knock", "The password is knock knock knock")]
        public void OtherSecretsAreMaskedSecretsMaskerVSO(string input, string expected)
        {
            // Arrange.

            Environment.SetEnvironmentVariable("AZP_ENABLE_OSS_SECRET_MASKER", null);
            Environment.SetEnvironmentVariable("AZP_ENABLE_NEW_SECRET_MASKER", null);

            using (var _hc = Setup())
            {
                // Act.
                var result = _hc.SecretMasker.MaskSecrets(input);

                // Assert.
                Assert.Equal(expected, result);
            }
        }

        [Fact]
        public void LogFileChangedAccordingToEnvVariable()
        {
            try
            {
                var newPath = Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "logs");
                Environment.SetEnvironmentVariable("AGENT_DIAGLOGPATH", newPath);

                using (var _hc = new HostContext(HostType.Agent))
                {
                    // Act.
                    var diagFolder = _hc.GetDiagDirectory();

                    // Assert
                    Assert.Equal(Path.Combine(newPath, Constants.Path.DiagDirectory), diagFolder);
                    Directory.Exists(diagFolder);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("AGENT_DIAGLOGPATH", null);
            }
        }

        public HostContext Setup([CallerMemberName] string testName = "")
        {
            var hc = new HostContext(
                hostType: HostType.Agent,
                logFile: Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), $"trace_{nameof(HostContextL0)}_{testName}.log"));
            return hc;
        }
    }
}
