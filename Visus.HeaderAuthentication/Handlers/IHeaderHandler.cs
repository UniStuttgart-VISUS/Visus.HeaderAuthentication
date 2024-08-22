// <copyright file="IHeaderAuthenticationHandler.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.Extensions.Primitives;
using System.Security.Claims;
using System.Threading.Tasks;
using Visus.HeaderAuthentication.Configuration;


namespace Visus.HeaderAuthentication.Handlers {

    /// <summary>
    /// Provides a bunch of default values for
    /// <see cref="HeaderAuthenticationOptions.AuthenticateAsync"/>.
    /// </summary>
    public interface IHeaderHandler {

        #region Public properties
        /// <summary>
        /// Gets the authentication type set for the
        /// <see cref="ClaimsIdentity"/> that is created by
        /// <see cref="AuthenticateAsync(StringValues)"/>.
        /// </summary>
        string? AuthenticationType { get; }
        #endregion

        #region Public methods
        /// <summary>
        /// Answer the <see cref="ClaimsPrincipal"/> for the first of the given
        /// header <paramref name="values"/> that can be authenticated.
        /// </summary>
        /// <param name="values">The values of the authentication header.
        /// </param>
        /// <returns>The principal that could be authenticated successfully, or
        /// <c>null</c> if none of the values was valid.</returns>
        /// <exception cref="System.ArgumentNullException">If
        /// <paramref name="values"/> is <c>null</c>.</exception>
        Task<ClaimsPrincipal?> AuthenticateAsync(StringValues values);
        #endregion
    }
}
