// <copyright file="HeaderAuthenticationHandler.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Visus.HeaderAuthentication.Configuration;
using Visus.HeaderAuthentication.Properties;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// A custom authentication handler that checks for a token in one of
    /// the configured HTTP headers.
    /// </summary>
    /// <param name="options">The monitor for the options instance.</param>
    /// <param name="loggerFactory">A factory for <see cref="ILogger"/>s to
    /// be used by the handler</param>
    /// <param name="urlEncoder">An URL encoder.</param>
    /// <param name="clock">A time provider.</param>
    internal sealed class HeaderAuthenticationHandler(
            IOptionsMonitor<HeaderAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder urlEncoder,
            ISystemClock clock)
        : AuthenticationHandler<HeaderAuthenticationOptions>(
            options,
            loggerFactory,
            urlEncoder,
            clock) {

        #region Protected methods
        /// <inheritdoc />
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
            if (!this.Request.Headers.ContainsKey(this.Options.HeaderName)) {
                var msg = Resources.ErrorMissingHeader;
                msg = string.Format(msg, this.Options.HeaderName);
                return AuthenticateResult.Fail(msg);
            }

            var handler = this.Options.HeaderHandler;
            var value = this.Request.Headers[this.Options.HeaderName];
            this._logger.LogTrace("Authenticating with header {Header}", value);

            var principal = (handler != null)
                ? await handler.AuthenticateAsync(value)
                : null;
            if (principal == null) {
                this._logger.LogError("Authentication with header {HeaderName} "
                    + "failed.", this.Options.HeaderName);
                var msg = Resources.ErrorAuthenticationFailed;
                return AuthenticateResult.Fail(msg);
            }

            var ticket = new AuthenticationTicket(principal, this.Scheme.Name);
            this._logger.LogInformation("Authentication ticket issued based on "
                + "header {HeaderName}.", this.Options.HeaderName);

            return AuthenticateResult.Success(ticket);
        }
        #endregion

        #region Private fields
        private readonly ILogger _logger = loggerFactory.CreateLogger<
            HeaderAuthenticationHandler>();
        #endregion
    }
}
