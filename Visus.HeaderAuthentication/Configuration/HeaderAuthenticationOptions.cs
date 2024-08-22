// <copyright file="HeaderAuthenticationOptions.cs" company="Visualisierungsinstitut der Universität Stuttgart">
// Copyright © 2024 Visualisierungsinstitut der Universität Stuttgart.
// Licensed under the MIT licence. See LICENCE file for more information.
// </copyright>
// <author>Christoph Müller</author>

using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Visus.HeaderAuthentication.Handlers;
using Visus.HeaderAuthentication.Properties;


namespace Visus.HeaderAuthentication.Configuration {

    /// <summary>
    /// Configures header-based authentication.
    /// </summary>
    public sealed class HeaderAuthenticationOptions
            : AuthenticationSchemeOptions {

        #region Public constants
        /// <summary>
        /// The suggested name of the authentication scheme.
        /// </summary>
        public const string DefaultScheme = "HeaderAuthenticationScheme";

        /// <summary>
        /// The name of the configuration section to be mapped to this object.
        /// </summary>
        public const string Section = "HeaderAuthentication";
        #endregion

        #region Public properties
        /// <summary>
        /// Gets or sets the name of the header to be used for authentication.
        /// </summary>
        /// <remarks>
        /// This value defaults to the typical &quot;Authorization&quot; header.
        /// </remarks>
        public string HeaderName { get; set; } = "Authorization";

        /// <summary>
        /// Gets or sets a handler for authenticating a user based on the given
        /// header values.
        /// </summary>
        /// <remarks>
        /// <para>This handler should create a <see cref="ClaimsPrincipal"/> for
        /// the provided authentication values or return <c>null</c> if the
        /// authentication was not possible with the data provided.</para>
        /// <para>Note that this property defaults to a handler that never
        /// succeeds, so you must change this property to any implementation that
        /// suits your need. There are some default implementations provided in
        /// the library, for instance
        /// <see cref="Handlers.TokenHeaderHandler"/> for
        /// validating token headers.</para>
        /// </remarks>
        public IHeaderHandler HeaderHandler { get; set; } = null!;
        #endregion

        #region Public methods
        /// <inheritdoc />
        public override void Validate(string scheme) {
            base.Validate(scheme);

            if (string.IsNullOrWhiteSpace(this.HeaderName)) {
                throw new ValidationException(Resources.ErrorMissingHeader);
            }

            if (this.HeaderHandler == null) {
                throw new ValidationException(
                    Resources.ErrorMissingHeaderAuthenticationHandler);
            }
        }
        #endregion
    }
}
