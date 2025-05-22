
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
using System;

namespace Agent.Sdk.SecretMasking
{
    /// <summary>
    /// Extended secret masker service that allows specifying the origin of any
    /// masking operation. It works by wrapping an existing IRawSecretMasker
    /// implementation and an optionally settable ITraceWriter instance for
    /// secret origin logging operations. In the agent today, this class can be
    /// initialized with two distinct IRawSecretMasker implementations, the one
    /// that ships in VSO itself, and the official Microsoft open source secret
    /// masker, implemented at https://github/microsoft/security-utilities.
    /// </summary>
    public class LoggedSecretMasker : ILoggedSecretMasker
    {
        private IRawSecretMasker _secretMasker;
        private ITraceWriter _trace;

        private void Trace(string msg)
        {
            this._trace?.Info(msg);
        }

        public LoggedSecretMasker(IRawSecretMasker secretMasker)
        {
            this._secretMasker = secretMasker;
        }

        public void SetTrace(ITraceWriter trace)
        {
            this._trace = trace;
        }

        public void AddValue(string pattern)
        {
            this._secretMasker.AddValue(pattern);
        }

        /// <summary>
        /// Overloading of AddValue method with additional logic for logging origin of provided secret
        /// </summary>
        /// <param name="value">Secret to be added</param>
        /// <param name="origin">Origin of the secret</param>
        public void AddValue(string value, string origin)
        {
            // WARNING: Do not log the value here, it is a secret!
            this.Trace($"Setting up value for origin: {origin}");
            if (value == null)
            {
                this.Trace($"Value is empty.");
                return;
            }

            AddValue(value);
        }
        public void AddRegex(string pattern)
        {
            this._secretMasker.AddRegex(pattern);
        }

        /// <summary>
        /// Overloading of AddRegex method with additional logic for logging origin of provided secret
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="origin"></param>
        public void AddRegex(string pattern, string origin)
        {
            // WARNING: Do not log the pattern here, it could be very specifc and contain a secret!
            this.Trace($"Setting up regex for origin: {origin}.");
            if (pattern == null)
            {
                this.Trace($"Pattern is empty.");
                return;
            }

            AddRegex(pattern);
        }

        // We don't allow to skip secrets longer than 5 characters.
        // Note: the secret that will be ignored is of length n-1.
        public static int MinSecretLengthLimit => 6;

        public int MinSecretLength
        {
            get
            {
                return _secretMasker.MinSecretLength;
            }
            set
            {
                if (value > MinSecretLengthLimit)
                {
                    _secretMasker.MinSecretLength = MinSecretLengthLimit;
                }
                else
                {
                    _secretMasker.MinSecretLength = value;
                }
            }
        }

        public void RemoveShortSecretsFromDictionary()
        {
            this._trace?.Info("Removing short secrets from masking dictionary");
            _secretMasker.RemoveShortSecretsFromDictionary();
        }

        public void AddValueEncoder(Func<string, string> encoder)
        {
            this._secretMasker.AddValueEncoder(encoder);
        }

        /// <summary>
        /// Overloading of AddValueEncoder method with additional logic for logging origin of provided secret
        /// </summary>
        /// <param name="encoder"></param>
        /// <param name="origin"></param>
        public void AddValueEncoder(Func<string, string> encoder, string origin)
        {
            this.Trace($"Setting up value for origin: {origin}");
            if (encoder == null)
            {
                this.Trace($"Encoder is empty.");
                return;
            }

            AddValueEncoder(encoder);
        }

        public string MaskSecrets(string input)
        {
            return this._secretMasker.MaskSecrets(input);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (_secretMasker is IDisposable disposable)
                {
                    disposable.Dispose();
                }
                _secretMasker = null;
            }
        }
    }
}
