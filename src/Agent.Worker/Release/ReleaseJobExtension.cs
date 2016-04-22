using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

using Agent.Worker.Release;
using Agent.Worker.Release.Artifacts.Definition;

using Microsoft.TeamFoundation.DistributedTask.WebApi;
using Microsoft.VisualStudio.Services.Agent.Util;
using Microsoft.VisualStudio.Services.ReleaseManagement.WebApi.Contracts;

namespace Microsoft.VisualStudio.Services.Agent.Worker.Release
{
    public sealed class ReleaseJobExtension : AgentService, IJobExtension
    {
        public Type ExtensionType => typeof(IJobExtension);

        public string HostType => "release";

        public IStep PrepareStep { get; private set; }

        public IStep FinallyStep { get; private set; }

        // TODO: These methods seems not relevant to Release Extension, refactor it
        public string GetRootedPath(IExecutionContext context, string path)
        {
            throw new NotImplementedException();
        }

        public void ConvertLocalPath(IExecutionContext context, string localPath, out string repoName, out string sourcePath)
        {
            throw new NotImplementedException();
        }

        public ReleaseJobExtension()
        {
            PrepareStep = new JobExtensionRunner(
                runAsync: PrepareAsync,
                alwaysRun: false,
                continueOnError: false,
                critical: true,
                displayName: StringUtil.Loc("DownloadArtifacts"),
                enabled: true,
                @finally: false);
        }

        public async Task PrepareAsync()
        {
            Trace.Entering();

            ArgUtil.NotNull(PrepareStep, nameof(PrepareStep));
            ArgUtil.NotNull(PrepareStep.ExecutionContext, nameof(PrepareStep.ExecutionContext));

            int releaseId;
            Guid teamProjectId;
            string artifactsWorkingFolder;
            bool skipArtifactsDownload;

            IExecutionContext executionContext = PrepareStep.ExecutionContext;
            InitializeAgent(executionContext, out skipArtifactsDownload, out teamProjectId, out artifactsWorkingFolder, out releaseId);

            if (!skipArtifactsDownload)
            {
                // TODO: Create this as new task. Old windows agent does this. First is initialize which does the above and download task will be added based on skipDownloadArtifact option
                executionContext.Output("Downloading artifact");

                await DownloadArtifacts(executionContext, teamProjectId, artifactsWorkingFolder, releaseId);
            }
        }

        private async Task DownloadArtifacts(
            IExecutionContext executionContext,
            Guid teamProjectId,
            string artifactsWorkingFolder,
            int releaseId)
        {
            Trace.Entering();

            ServiceEndpoint vssEndpoint = executionContext.Endpoints.FirstOrDefault(e => string.Equals(e.Name, ServiceEndpoints.SystemVssConnection, StringComparison.OrdinalIgnoreCase));
            ArgUtil.NotNull(vssEndpoint, nameof(vssEndpoint));
            ArgUtil.NotNull(vssEndpoint.Url, nameof(vssEndpoint.Url));

            Trace.Info($"Connecting to {vssEndpoint.Url}/{teamProjectId}");
            var releaseServer = new ReleaseServer(vssEndpoint.Url, ApiUtil.GetVssCredential(vssEndpoint), teamProjectId);

            // TODO: send correct cancellation token
            List<AgentArtifactDefinition> releaseArtifacts =
                releaseServer.GetReleaseArtifactsFromService(releaseId).ToList();

            releaseArtifacts.ForEach(x => Trace.Info($"Found Artifact = {x.Alias}"));

            CleanUpArtifactsFolder(executionContext, artifactsWorkingFolder);
            await DownloadArtifacts(executionContext, releaseArtifacts, artifactsWorkingFolder);
        }

        private async Task DownloadArtifacts(IExecutionContext executionContext, List<AgentArtifactDefinition> agentArtifactDefinitions, string artifactsWorkingFolder)
        {
            Trace.Entering();

            foreach (AgentArtifactDefinition agentArtifactDefinition in agentArtifactDefinitions)
            {
                // We don't need to check if its old style artifact anymore. All the build data has been fixed and all the build artifact has Alias now.
                ArgUtil.NotNullOrEmpty(agentArtifactDefinition.Alias, nameof(agentArtifactDefinition.Alias));

                var extensionManager = HostContext.GetService<IExtensionManager>();
                IArtifactExtension extension = (extensionManager.GetExtensions<IArtifactExtension>()).FirstOrDefault(x => agentArtifactDefinition.ArtifactType == x.ArtifactType);

                if (extension == null)
                {
                    throw new InvalidOperationException(StringUtil.Loc("RMArtifactTypeNotSupported"));
                }

                Trace.Info($"Found artifact extension of type {extension.ArtifactType}");
                executionContext.Output(StringUtil.Loc("RMStartArtifactsDownload"));
                ArtifactDefinition artifactDefinition = ConvertToArtifactDefinition(agentArtifactDefinition, executionContext, extension);
                executionContext.Output(StringUtil.Loc("RMArtifactDownloadBegin", agentArtifactDefinition.Alias));
                executionContext.Output(StringUtil.Loc("RMDownloadArtifactType", agentArtifactDefinition.ArtifactType));

                // Get the local path where this artifact should be downloaded. 
                string downloadFolderPath = Path.GetFullPath(Path.Combine(artifactsWorkingFolder, agentArtifactDefinition.Alias ?? string.Empty));

                // Create the directory if it does not exist. 
                if (!Directory.Exists(downloadFolderPath))
                {
                    // TODO: old windows agent has a directory cache, verify and implement it if its required.
                    Directory.CreateDirectory(downloadFolderPath);
                    executionContext.Output(StringUtil.Loc("RMArtifactFolderCreated", downloadFolderPath));
                }

                // download the artifact to this path. 
                RetryExecutor retryExecutor = new RetryExecutor();
                await retryExecutor.ExecuteAsync(
                    async () =>
                        {
                            //TODO:SetAttributesToNormal
                            var releaseFileSystemManager = HostContext.GetService<IReleaseFileSystemManager>();
                            releaseFileSystemManager.CleanupDirectory(downloadFolderPath, executionContext.CancellationToken);

                            if (agentArtifactDefinition.ArtifactType == AgentArtifactType.GitHub
                                || agentArtifactDefinition.ArtifactType == AgentArtifactType.TFGit
                                || agentArtifactDefinition.ArtifactType == AgentArtifactType.Tfvc)
                            {
                                throw new NotImplementedException();
                            }
                            else
                            {
                                await extension.DownloadAsync(executionContext, artifactDefinition, downloadFolderPath);
                            }
                        });

                executionContext.Output(StringUtil.Loc("RMArtifactDownloadFinished", agentArtifactDefinition.Alias));
            }

            executionContext.Output(StringUtil.Loc("RMArtifactsDownloadFinished"));
        }

        private void CleanUpArtifactsFolder(IExecutionContext executionContext, string artifactsWorkingFolder)
        {
            Trace.Entering();
            executionContext.Output(StringUtil.Loc("RMCleaningArtifactsDirectory", artifactsWorkingFolder));
            try
            {
                IOUtil.DeleteDirectory(artifactsWorkingFolder, executionContext.CancellationToken);
            }
            catch (Exception ex)
            {
                Trace.Error(ex);
                // Do not throw here
            }
            finally
            {
                executionContext.Output(StringUtil.Loc("RMCleanedUpArtifactsDirectory", artifactsWorkingFolder));
            }
        }

        private void InitializeAgent(IExecutionContext executionContext, out bool skipArtifactsDownload, out Guid teamProjectId, out string artifactsWorkingFolder, out int releaseId)
        {
            Trace.Entering();

            releaseId = executionContext.Variables.GetInt(Constants.Variables.Release.ReleaseId) ?? 0;
            teamProjectId = executionContext.Variables.GetGuid(Constants.Variables.System.TeamProjectId) ?? Guid.Empty;
            skipArtifactsDownload = executionContext.Variables.GetBoolean(Constants.Variables.Release.SkipArtifactsDownload) ?? false;
            string releaseDefinitionName = executionContext.Variables.Get(Constants.Variables.Release.ReleaseDefinitionName);

            // TODO: Should we also write to log in executionContext.Output methods? so that we don't have to repeat writing into logs?
            // Log these values here to debug scenarios where downloading the artifact fails.
            executionContext.Output(
                $"ReleaseId={releaseId}, TeamProjectId={teamProjectId}, ReleaseDefinitionName={releaseDefinitionName}");

            // TODO: Remove shorthash, you may get into collision. Switch to increment integer
            var configStore = HostContext.GetService<IConfigurationStore>();
            var shortHash = ReleaseFolderHelper.CreateShortHash(
                configStore.GetSettings().AgentName,
                teamProjectId.ToString(),
                releaseDefinitionName);
            executionContext.Output($"Release folder: {shortHash}");

            artifactsWorkingFolder = Path.Combine(IOUtil.GetWorkPath(HostContext), shortHash);
            SetLocalVariables(executionContext, artifactsWorkingFolder);

            // Log the environment variables available after populating the variable service with our variables
            LogEnvironmentVariables(executionContext);

            if (skipArtifactsDownload)
            {
                // If this is the first time the agent is executing a task, we need to create the artifactsFolder
                // otherwise Process.StartWithCreateProcess() will fail with the error "The directory name is invalid"
                // because the working folder doesn't exist
                CreateWorkingFolderIfRequired(executionContext, artifactsWorkingFolder);

                // log the message that the user chose to skip artifact download and move on
                executionContext.Output(StringUtil.Loc("RMUserChoseToSkipArtifactDownload"));
                Trace.Info("Skipping artifact download based on the setting specified.");
            }
        }

        private void SetLocalVariables(IExecutionContext executionContext, string artifactsDirectoryPath)
        {
            Trace.Entering();

            // Always set the AgentReleaseDirectory because this is set as the WorkingDirectory of the task.
            executionContext.Variables.Set(WellKnownReleaseVariables.AgentReleaseDirectory, artifactsDirectoryPath);

            // Set the ArtifactsDirectory even when artifacts downloaded is skipped. Reason: The task might want to access the old artifact.
            executionContext.Variables.Set(WellKnownReleaseVariables.ArtifactsDirectory, artifactsDirectoryPath);
            executionContext.Variables.Set(Constants.Variables.System.DefaultWorkingDirectory, artifactsDirectoryPath);
        }

        private void LogEnvironmentVariables(IExecutionContext executionContext)
        {
            Trace.Entering();
            string stringifiedEnvironmentVariables = AgentUtilities.GetPrintableEnvironmentVariables(executionContext.Variables.Public);

            // Use LogMessage to ensure that the logs reach the TWA UI, but don't spam the console cmd window
            executionContext.Output(StringUtil.Loc("RMEnvironmentVariablesAvailable", stringifiedEnvironmentVariables));
        }

        private void CreateWorkingFolderIfRequired(IExecutionContext executionContext, string artifactsFolderPath)
        {
            Trace.Entering();
            if (!Directory.Exists(artifactsFolderPath))
            {
                executionContext.Output($"Creating artifacts folder: {artifactsFolderPath}");
                Directory.CreateDirectory(artifactsFolderPath);
            }
        }

        private ArtifactDefinition ConvertToArtifactDefinition(AgentArtifactDefinition agentArtifactDefinition, IExecutionContext executionContext, IArtifactExtension extension)
        {
            Trace.Entering();

            ArgUtil.NotNull(agentArtifactDefinition, nameof(agentArtifactDefinition));
            ArgUtil.NotNull(executionContext, nameof(executionContext));

            var artifactDefinition = new ArtifactDefinition
            {
                ArtifactType = agentArtifactDefinition.ArtifactType,
                Name = agentArtifactDefinition.Name,
                Version = agentArtifactDefinition.Version
            };

            artifactDefinition.Details = extension.GetArtifactDetails(executionContext, agentArtifactDefinition);
            return artifactDefinition;
        }
    }
}