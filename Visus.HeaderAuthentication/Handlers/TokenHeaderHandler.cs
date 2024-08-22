// <copyright file="TokenHeaderHandler.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// Tries authenticating the given header values as authentication tokens.
    /// </summary>
    public sealed class TokenHeaderHandler : HeaderHandlerBase {

        #region Public constants
        /// <summary>
        /// The default value for <see cref="HeaderHandlerBase.Scheme"/>.
        /// </summary>
        public const string DefaultScheme = "Token";
        #endregion

        #region Public constructors
        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in
        /// the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="validateToken">The handler that checks whether a token
        /// is valid or not.</param>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="validateToken"/> is <c>null</c>.</exception>
        public TokenHeaderHandler(string authenticationType,
                Func<string, Task<IEnumerable<Claim>>> validateToken)
                : base(authenticationType, DefaultScheme) {
            this.ValidateAsync = validateToken
                ?? throw new ArgumentNullException(nameof(validateToken));
        }

        /// <summary>
        /// Initialises a new intance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in
        /// the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="tokens">The list of valid tokens.</param>
        public TokenHeaderHandler(string authenticationType,
                IEnumerable<string> tokens)
                : base(authenticationType, DefaultScheme) {
            if ((tokens != null) && tokens.Any()) {
                this.ValidateAsync = i => Task.FromResult(
                    GetClaim(tokens.First(t => t == i)));
            }
        }

        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in
        /// the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="token">The single valid token.</param>
        public TokenHeaderHandler(string authenticationType, string token)
                : base(authenticationType, DefaultScheme) {
            if (!string.IsNullOrWhiteSpace(token)) {
                this.ValidateAsync = i => (i == token)
                    ? Task.FromResult(GetClaim(i))
                    : Task.FromResult(Enumerable.Empty<Claim>());
            }
        }
        #endregion

        #region Public properties
        /// <summary>
        /// Gets the callback used to validate the token.
        /// </summary>
        /// <remarks>
        /// The callback shall yield at least one <see cref="Claim"/> if the
        /// token is valid, or an empty enumeration otherwise.
        /// </remarks>
        public Func<string, Task<IEnumerable<Claim>>> ValidateAsync {
            get;
        } = Invalid;
        #endregion

        #region Public methods
        /// <inheritdoc />
        public override async Task<ClaimsPrincipal?> AuthenticateAsync(
                StringValues values) {
            foreach (var h in this.Parse(values)) {
                if (h.Parameter == null) {
                    continue;
                }

                var claims = await this.ValidateAsync(h.Parameter);
                if (claims.Any()) {
                    return this.ToPrincial(claims);
                }
            }

            return null;
        }
        #endregion

        #region Private class properties
        /// <summary>
        /// A validator that always fails.
        /// </summary>
        private static Func<string, Task<IEnumerable<Claim>>> Invalid
            = _ => Task.FromResult(Enumerable.Empty<Claim>());
        #endregion

        #region Private class methods
        /// <summary>
        /// Constructs a claim for the given token.
        /// </summary>
        private static IEnumerable<Claim> GetClaim(string token)
            => [new(ClaimTypes.Authentication, token)];
        #endregion
    }
}
