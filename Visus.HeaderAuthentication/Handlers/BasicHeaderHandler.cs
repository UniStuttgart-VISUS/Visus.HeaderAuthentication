// <copyright file="BasicHeaderHandler.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.Primitives;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// Tries authenticating the given header values using the basic access
    /// authentication method.
    /// </summary>
    public sealed class BasicHeaderHandler : HeaderHandlerBase {

        #region Public constants
        /// <summary>
        /// The default value for <see cref="HeaderHandlerBase.Scheme"/>.
        /// </summary>
        public const string DefaultScheme = "Basic";
        #endregion

        #region Public constructors
        /// <summary>
        /// Initialises a new instance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in
        /// the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="validateUser">The handler that checks whether a given
        /// combindation of user name and password is valid or not.</param>
        /// <exception cref="ArgumentNullException">If
        /// <paramref name="validateUser"/> is <c>null</c>.</exception>
        public BasicHeaderHandler(string authenticationType,
                Func<string, string, Task<IEnumerable<Claim>>> validateUser)
                : base(authenticationType, DefaultScheme) {
            this.ValidateAsync = validateUser
                ?? throw new ArgumentNullException(nameof(validateUser));
        }

        /// <summary>
        /// Initialises a new intance.
        /// </summary>
        /// <param name="authenticationType">The authentication type set in
        /// the <see cref="ClaimsIdentity"/>.</param>
        /// <param name="users">A list of valid users and their passwords.
        /// </param>
        public BasicHeaderHandler(string authenticationType,
                IDictionary<string, string> users)
                : base(authenticationType, DefaultScheme) {
            if ((users == null) || !users.Any()) {
                this.ValidateAsync = Invalid;
            } else {
                this.ValidateAsync = (u, p) => {
                    if (users.TryGetValue(u, out var password)) {
                        if (p == password) {
                            return Task.FromResult(GetClaim(u));
                        }
                    }

                    return Task.FromResult(Enumerable.Empty<Claim>());
                };
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
        public Func<string, string, Task<IEnumerable<Claim>>> ValidateAsync {
            get;
        } = Invalid;
        #endregion

        #region Public methods
        /// <inheritdoc />
        public override async Task<ClaimsPrincipal?> AuthenticateAsync(
                StringValues values) {
            // Cf. https://learn.microsoft.com/de-de/aspnet/web-api/overview/security/basic-authentication

            foreach (var h in this.Parse(values)) {
                if (h.Parameter == null) {
                    continue;
                }

                var encoded = Convert.FromBase64String(h.Parameter);
                var credentials = this._encoding.GetString(encoded);
                int split = credentials.IndexOf(':');
                var user = credentials.Substring(0, split);
                var password = credentials.Substring(split + 1);

                var claims = await this.ValidateAsync(user, password);
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
        private static Func<string, string, Task<IEnumerable<Claim>>> Invalid
            = (_, _) => Task.FromResult(Enumerable.Empty<Claim>());
        #endregion

        #region Private class methods
        /// <summary>
        /// Constructs a claim for the given <paramref name="user"/> name.
        /// </summary>
        private static IEnumerable<Claim> GetClaim(string user)
            => [new(ClaimTypes.Name, user)];
        #endregion

        #region Private fields
        private readonly Encoding _encoding = Encoding.GetEncoding("iso-8859-1");
        #endregion
    }
}
