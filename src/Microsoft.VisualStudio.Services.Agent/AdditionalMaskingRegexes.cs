// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace Microsoft.VisualStudio.Services.Agent
{
    public static partial class AdditionalMaskingRegexes
    {
        public static string UrlSecretPattern => "(ftps?|https?):\\/\\/(?:[^:@\\/]+):[^:@?\\/]+@";
    }
}