namespace SafeNet.Acl.Test {
    using System;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.AccessControl;
    using System.Security.Principal;

    using FluentAssertions;

    using Moq;

    using Ploeh.AutoFixture;
    using Ploeh.AutoFixture.Kernel;
    using Ploeh.AutoFixture.Xunit;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;
    using SafeNet.Test.Common;

    using Xunit;
    using Xunit.Extensions;

    public class FileAclSafeTests : IDisposable {
        private readonly Mock<EnvironmentWrapper> environmentMock;

        private readonly string expectedFileName;

        private readonly Testable<FileAclSafe> testable;

        public FileAclSafeTests() {
            this.testable = new Testable<FileAclSafe>();
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
            this.expectedFileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            this.testable.Fixture.Register(() => new SecureString());
        }

        public void Dispose() {
            if (File.Exists(this.expectedFileName)) {
                File.Delete(this.expectedFileName);
            }
        }

        [Fact]
        public void Protect_AssignsFileSystemAccessRulesToSafe() {
            this.RegisterCurrentUserInFixture();
            var realFile = this.RegisterRandomFileAsSafe(writeText: true);
            var security = realFile.GetAccessControl();

            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Verifiable();

            this.testable.ClassUnderTest.Protect(security);
            this.environmentMock.Verify(
                x => x.SetAccessControl(this.testable.ClassUnderTest.SafeObject, security),
                Times.Once());
        }

        [Fact]
        public void Protect_WithRulesAssignsRulesToSafe() {
            this.RegisterCurrentUserInFixture();
            this.RegisterRandomFileAsSafe(this.expectedFileName, writeText: true);
            this.testable.Fixture.Register(() => InheritanceFlags.None);
            this.testable.Fixture.Register(() => PropagationFlags.None);
            var expectedRules = this.testable.Fixture.CreateMany<FileSystemAccessRule>().ToList();

            FileSystemSecurity actualSecurity = null;
            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Callback<FileSystemInfo, FileSystemSecurity>((x, y) => actualSecurity = y);

            this.testable.ClassUnderTest.Protect(expectedRules);

            var actualRules = actualSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

            actualRules.ShouldBeEquivalentTo(expectedRules);
        }

        [Fact]
        public void RetrieveSecret_OnlyTarget_ExpectSafeSearchNone() {
            this.RegisterCurrentUserInFixture();
            var realFile = this.RegisterRandomFileAsSafe(writeText: true);
            this.testable.Fixture.Register(realFile.GetAccessControl);
            var storage = this.testable.InjectMock<IStorageSchema>();
            storage.Setup(x => x.ReadSecret(It.IsAny<string>(), SafeSearchMethod.None)).Verifiable();

            this.testable.ClassUnderTest.RetrieveSecret(this.testable.Fixture.Create<string>());

            storage.Verify(x => x.ReadSecret(It.IsAny<string>(), SafeSearchMethod.None));
        }

        [Fact]
        public void WhenConstructedAndFileExistsNoChange() {
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(true).Verifiable();

            var actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()), Times.Never());
        }

        [Fact]
        public void WhenConstructedGivenNonExistantSafeFileCreatesFileAndDirectoryStructure() {
            var safe = this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(false).Verifiable();

            var actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.CreateDirectory(safe.DirectoryName), Times.Once());
            this.environmentMock.Verify(x => x.WriteAllText(this.expectedFileName, It.IsAny<string>()), Times.Once());
        }

        [Theory, Integration, AutoData]
        public void GivenSafeStringPathCanStoreSecret(Secret expectedSecret) {
            var safe = new FileAclSafe(this.expectedFileName);
            safe.StoreSecret(expectedSecret);

            var actualSecret = safe.RetrieveSecret(expectedSecret.Target);

            AssertEx.CompareSecrets(actualSecret, expectedSecret);
        }

        [Theory, AutoData]
        public void Upsert_IfCredentialDoesNotExist_ExpectInserted(Secret expectedSecret) {
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(It.IsAny<string>())).Returns(true);

            var mockStorage = this.testable.InjectMock<IStorageSchema>();
            mockStorage.Setup(x => x.ReadSecret(It.IsAny<string>(), It.IsAny<SafeSearchMethod>()))
                .Returns<ISecret>(null);

            mockStorage.Setup(x => x.WriteSecret(It.IsAny<ISecret>())).Verifiable();

            this.testable.ClassUnderTest.UpsertSecret(expectedSecret);

            mockStorage.Verify(x => x.WriteSecret(expectedSecret), Times.Once());
        }

        [Theory, AutoData]
        public void Upsert_IfCredentialExists_ExpectWriteWith(Secret expectedSecret, Secret actualSecret) {            
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(It.IsAny<string>())).Returns(true);

            var mockStorage = this.testable.InjectMock<IStorageSchema>();
            mockStorage.Setup(x => x.ReadSecret(It.IsAny<string>(), It.IsAny<SafeSearchMethod>()))
                .Returns(actualSecret);

            ISecret writtenSecret = null;
            mockStorage.Setup(x => x.WriteSecret(It.IsAny<ISecret>()))
                .Callback<ISecret>(x => writtenSecret = x);

            this.testable.ClassUnderTest.UpsertSecret(expectedSecret);

            AssertEx.CompareSecrets(writtenSecret, expectedSecret, false);
            writtenSecret.Identifier.Should().Be(actualSecret.Identifier);
        }

        private void RegisterCurrentUserInFixture() {
            this.testable.Fixture.Register<IdentityReference>(() => new NTAccount(WindowsIdentity.GetCurrent().Name));
        }

        private FileInfo RegisterRandomFileAsSafe(bool writeText = false) {
            return this.RegisterRandomFileAsSafe(this.expectedFileName, writeText);
        }

        private FileInfo RegisterRandomFileAsSafe(string path, bool writeText = false) {
            if (writeText) {
                File.WriteAllText(path, string.Empty);
            }
            var safe = new FileInfo(path);
            this.testable.Fixture.Register(() => safe);

            return safe;
        }
    }
}