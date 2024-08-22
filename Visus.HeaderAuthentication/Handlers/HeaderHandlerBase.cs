// <copyright file="HeaderHandlerBase.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// Base class for authentication handlers that parse an RFC 2617
    /// authentication header.
    /// </summary>
    public abstract class HeaderHandlerBase : IHeaderHandler {

        #region Public properties
        /// <inheritdoc />
        public string AuthenticationType { get; }

        /// <summary>
        /// Gets or sets the scheme that is expected in the header.
        /// </summary>
        public string Scheme { get; set; }
        #endregion

        #region Public methods
        /// <inheritdoc />
        public abstract Task<ClaimsPrincipal?> AuthenticateAsync(
            StringValues values);
        #endregion

        #region Protected constructors
        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in the
        /// <see cref="ClaimsIdentity"/> created by the handler.</param>
        /// <param name="scheme">The RFC 2617 scheme the handler expects.
        /// </param>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="authenticationType"/> is <c>null</c>, or if
        /// <paramref name="scheme"/> is <c>null</c>.</exception>
        protected HeaderHandlerBase(
                string authenticationType,
                string scheme) {
            this.AuthenticationType = authenticationType
                ?? throw new ArgumentNullException(nameof(authenticationType));
            this.Scheme = scheme
                ?? throw new ArgumentNullException(nameof(scheme));
        }
        #endregion

        #region Protected methods
        /// <summary>
        /// Enumerates all <see cref="AuthenticationHeaderValue"/>s that match
        /// the configured <see cref="Scheme"/>.
        /// </summary>
        /// <param name="values">The header values to be parsed.</param>
        /// <returns>All matching authentication headers.</returns>
        /// <exception cref="ArgumentNullException">If <paramref name="values"/>
        /// is <c>null</c>.</exception>
        protected IEnumerable<AuthenticationHeaderValue> Parse(
                StringValues values) {
            ArgumentNullException.ThrowIfNull(values, nameof(values));

            foreach (var v in values) {
                if (v == null) {
                    continue;
                }

                var header = AuthenticationHeaderValue.Parse(v);
                if (header == null) {
                    continue;
                }

                if (!this.Scheme.Equals(header.Scheme,
                        StringComparison.OrdinalIgnoreCase)) {
                    continue;
                }

                yield return header;
            }
        }

        /// <summary>
        /// Creates a new <see cref="ClaimsIdentity"/> from the given
        /// <paramref name="claims"/> and the configured
        /// <see cref="AuthenticationType"/> and wraps it in a
        /// <see cref="ClaimsPrincipal"/>.
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException">If <paramref name="claims"/>
        /// is <c>null</c>.</exception>
        protected ClaimsPrincipal ToPrincial(IEnumerable<Claim> claims) {
            ArgumentNullException.ThrowIfNull(claims, nameof(claims));
            var identity = new ClaimsIdentity(claims, this.AuthenticationType);
            return new ClaimsPrincipal(identity);
        }
        #endregion
    }
}
